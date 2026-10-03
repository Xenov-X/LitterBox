# app/analyzers/fuzzy.py

import pyssdeep
import json
import os
import hashlib
import configparser
import threading
import zlib
from datetime import datetime
from typing import Dict, List, Optional, Tuple, Any
from pathlib import Path
import binascii
import re

# One lock for every read-modify-write of the database file, and a cache
# of the parsed database keyed by path -> (mtime_ns, size, db). The
# analyzer is constructed per request; without the cache every request
# (including the stats page) re-parsed the whole corpus.
_DB_LOCK = threading.RLock()
_DB_CACHE: Dict[str, Tuple[int, int, Dict]] = {}

# Upper bound on files indexed by one create_db_from_folder call.
_DEFAULT_MAX_INDEX_FILES = 10000

_SSDEEP_WINDOW = 7
_RUNS = re.compile(r'(.)\1{3,}')


def _ssdeep_parts(hash_value: str):
    """'bs:h1:h2' -> [(bs, h1), (2*bs, h2)] with runs of >3 identical
    characters collapsed, as ssdeep does before comparing."""
    try:
        bs, h1, h2 = hash_value.split(':', 2)
        bs = int(bs)
    except (ValueError, AttributeError):
        return []
    return [(bs, _RUNS.sub(r'\1\1\1', h1)), (bs * 2, _RUNS.sub(r'\1\1\1', h2))]


def _grams(text: str):
    return {text[i:i + _SSDEEP_WINDOW] for i in range(len(text) - _SSDEEP_WINDOW + 1)}


def _candidate_keys(hash_value: str):
    """(effective block size, 7-gram) keys for a hash. ssdeep scores two
    non-identical signatures above 0 only when parts at the same
    effective block size share a 7-character substring, so blocks that
    share no key can be skipped without changing any result."""
    keys = set()
    for size, part in _ssdeep_parts(hash_value):
        for gram in _grams(part):
            keys.add((size, gram))
    return keys


class BlockData:
    """A block's bytes. Kept zlib-compressed until displayed — the
    database holds every 4 KB block of the corpus, and decompressing all
    of them on load dominated request time and memory."""

    def __init__(self, raw_data: Optional[bytes], start_offset: int,
                 compressed_b64: Optional[str] = None, length: Optional[int] = None):
        self._raw = raw_data
        self._compressed_b64 = compressed_b64
        self.start_offset = start_offset
        self.length = len(raw_data) if raw_data is not None else (length or 0)

    @property
    def raw_data(self) -> bytes:
        if self._raw is None:
            self._raw = zlib.decompress(binascii.a2b_base64(self._compressed_b64))
            self.length = len(self._raw)
        return self._raw

    def _create_hex_dump(self) -> str:
        """Only created when displaying results"""
        hex_lines = []
        for i in range(0, self.length, 16):
            chunk = self.raw_data[i:i + 16]
            hex_values = ' '.join(f'{b:02x}' for b in chunk)
            hex_values = hex_values.ljust(48)
            hex_lines.append(f"{self.start_offset + i:08x}  {hex_values}")
        return '\n'.join(hex_lines)

    def _create_ascii_repr(self) -> str:
        """Only created when displaying results"""
        ascii_lines = []
        for i in range(0, self.length, 16):
            chunk = self.raw_data[i:i + 16]
            ascii_str = ''.join(chr(b) if 32 <= b <= 126 else '.' for b in chunk)
            ascii_lines.append(ascii_str)
        return '\n'.join(ascii_lines)

    def to_dict(self) -> Dict[str, Any]:
        """Store absolute minimum in DB, converting bytes to base64 string"""
        if self._compressed_b64 is None:
            self._compressed_b64 = binascii.b2a_base64(zlib.compress(self.raw_data)).decode('ascii').strip()
        return {
            "o": self.start_offset,  # Shortened key names
            "d": self._compressed_b64,
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any], length: Optional[int] = None) -> 'BlockData':
        """Reconstruct lazily — bytes are decompressed on first access."""
        return cls(None, data["o"], compressed_b64=data["d"], length=length)

class BlockMetadata:
    def __init__(self, index: int, block_size: int, hash_value: str, data: BlockData):
        self.index = index
        self.start_offset = data.start_offset
        self.end_offset = data.start_offset + data.length
        self.hash = hash_value
        self.data = data

    def to_dict(self) -> Dict[str, Any]:
        return {
            "i": self.index,  # Shortened key names
            "h": self.hash,
            "d": self.data.to_dict()
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any], block_size: int) -> 'BlockMetadata':
        # Every stored block is block_size bytes except possibly the last;
        # the exact length is filled in when the bytes are first read.
        block_data = BlockData.from_dict(data["d"], length=block_size)
        return cls(data["i"], block_size, data["h"], block_data)

class FileMetadata:
    def __init__(self, path: str, md5: str, file_size: int, blocks: List[BlockMetadata]):
        self.path = path
        self.md5 = md5
        self.file_size = file_size
        self.blocks = blocks
        self.date_added = datetime.now().isoformat()

    def to_dict(self) -> Dict[str, Any]:
        return {
            "p": self.path,  # Shortened key names
            "m": self.md5,
            "s": self.file_size,
            "b": [b.to_dict() for b in self.blocks],
            "d": self.date_added
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any], block_size: int) -> 'FileMetadata':
        blocks = [BlockMetadata.from_dict(b, block_size) for b in data["b"]]
        instance = cls(data["p"], data["m"], data["s"], blocks)
        instance.date_added = data.get("d", datetime.now().isoformat())
        return instance

class MatchingRegion:
    def __init__(self):
        self.source_start = 0
        self.target_start = 0
        self.length = 0
        self.total_similarity = 0
        self.blocks = 0
        self.source_data: List[BlockData] = []
        self.target_data: List[BlockData] = []

    def add_block(self, source_block: BlockMetadata, target_block: BlockMetadata, similarity: float):
        if self.blocks == 0:
            self.source_start = source_block.start_offset
            self.target_start = target_block.start_offset
            self.length = source_block.data.length
        else:
            self.length += source_block.data.length

        self.source_data.append(source_block.data)
        self.target_data.append(target_block.data)
        self.total_similarity += similarity
        self.blocks += 1

    @property
    def avg_similarity(self) -> float:
        return self.total_similarity / self.blocks if self.blocks > 0 else 0

    def to_dict(self) -> Dict[str, Any]:
        """When converting for display, create the ASCII and hex representations"""
        results = {
            "source_start": self.source_start,
            "target_start": self.target_start,
            "length": self.length,
            "avg_similarity": self.avg_similarity,
            "blocks": self.blocks,
            "source_data": [],
            "target_data": []
        }
        
        # Only create display data when needed
        for src_data in self.source_data:
            results["source_data"].append({
                "ascii_repr": src_data._create_ascii_repr(),
                "hex_dump": src_data._create_hex_dump()
            })
            
        for tgt_data in self.target_data:
            results["target_data"].append({
                "ascii_repr": tgt_data._create_ascii_repr(),
                "hex_dump": tgt_data._create_hex_dump()
            })
            
        return results

def _normalize_extensions(extensions) -> List[str]:
    """["exe", ".DLL", " bin "] -> [".exe", ".dll", ".bin"]"""
    if isinstance(extensions, str):
        extensions = extensions.split(',')
    result = []
    for ext in extensions or []:
        ext = str(ext).strip().lower()
        if not ext:
            continue
        result.append(ext if ext.startswith('.') else f'.{ext}')
    return result


class GitRepoInfo:
    def __init__(self, repo_path: str):
        self.repo_path = Path(repo_path)
        
    def get_remote_url(self) -> Optional[str]:
        """Extract the remote URL from .git/config"""
        try:
            git_config_path = self.repo_path / '.git' / 'config'
            if not git_config_path.exists():
                return None
                
            config = configparser.ConfigParser()
            config.read(git_config_path)
            
            for section in config.sections():
                if section.startswith('remote "origin"'):
                    url = config[section].get('url', '')
                    if url.startswith('git@github.com:'):
                        url = f"https://github.com/{url.split('git@github.com:')[1]}"
                    if url.endswith('.git'):
                        url = url[:-4]
                    return url
            return None
        except Exception:
            return None

class FuzzyHashAnalyzer:
    def __init__(self, config, logger=None):
        self.config = config
        self.logger = logger
        self.block_size = 4096
        # Get the base path and create full db path
        db_config = config['analysis']['doppelganger']['db']
        fuzzy_base = db_config['path']
        fuzzy_dir = db_config['fuzzyhash']
        self.db_path = os.path.join(fuzzy_base, fuzzy_dir, 'FuzzyHash.db')
        self.extensions = _normalize_extensions(db_config.get('fuzzy_extensions', []))
        self.allowed_roots = [os.path.abspath(r) for r in (db_config.get('fuzzy_allowed_roots') or [])]
        self.max_index_files = int(db_config.get('fuzzy_max_files', _DEFAULT_MAX_INDEX_FILES))
        self.db = self._load_db()

    def _serialize_db(self) -> bytes:
        data = {
            "sources": {
                source: {
                    "f": {  # Shortened key names
                        path: file_data.to_dict()
                        for path, file_data in source_data["files"].items()
                    },
                    "u": source_data["last_updated"]
                }
                for source, source_data in self.db["sources"].items()
            }
        }
        json_str = json.dumps(data, separators=(',', ':'))
        return zlib.compress(json_str.encode('utf-8'), level=9)

    def _write_db_bytes(self, payload: bytes):
        """Atomic write: a crash or a concurrent reader never sees a
        truncated database."""
        os.makedirs(os.path.dirname(self.db_path) or '.', exist_ok=True)
        tmp_path = f"{self.db_path}.tmp-{os.getpid()}-{threading.get_ident()}"
        with open(tmp_path, 'wb') as f:
            f.write(payload)
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp_path, self.db_path)

    def _save_db(self):
        """Save with maximum compression"""
        with _DB_LOCK:
            self._write_db_bytes(self._serialize_db())
            st = os.stat(self.db_path)
            _DB_CACHE[os.path.abspath(self.db_path)] = (st.st_mtime_ns, st.st_size, self.db)

    def _load_db(self) -> Dict:
        """Load the compressed database (cached by mtime/size)."""
        with _DB_LOCK:
            if not os.path.exists(self.db_path):
                if self.logger:
                    self.logger.debug(f"Database file {self.db_path} not found. Creating new database.")
                self._save_empty_db()
                return {"sources": {}}

            st = os.stat(self.db_path)
            key = os.path.abspath(self.db_path)
            cached = _DB_CACHE.get(key)
            if cached and cached[0] == st.st_mtime_ns and cached[1] == st.st_size:
                return cached[2]

            try:
                with open(self.db_path, 'rb') as f:
                    compressed_data = f.read()

                if not compressed_data:
                    return {"sources": {}}

                json_str = zlib.decompress(compressed_data).decode('utf-8')
                data = json.loads(json_str)

                # Convert shortened keys back
                converted = {"sources": {}}
                for source, sdata in data["sources"].items():
                    converted["sources"][source] = {
                        "files": {},
                        "last_updated": sdata["u"]
                    }
                    for path, fdata in sdata["f"].items():
                        converted["sources"][source]["files"][path] = FileMetadata.from_dict(
                            fdata, self.block_size
                        )
                _DB_CACHE[key] = (st.st_mtime_ns, st.st_size, converted)
                return converted

            except Exception as e:
                # Don't overwrite an unreadable database with an empty one —
                # move it aside so the indexed corpus can be recovered.
                corrupt_path = f"{self.db_path}.corrupt-{datetime.now().strftime('%Y%m%d%H%M%S')}"
                if self.logger:
                    self.logger.error(
                        f"Error loading fuzzy-hash database ({e}); moved it to {corrupt_path} "
                        f"and starting an empty one"
                    )
                try:
                    os.replace(self.db_path, corrupt_path)
                except OSError:
                    pass
                self._save_empty_db()
                return {"sources": {}}

    def _save_empty_db(self):
        """Initialize empty compressed database"""
        self._write_db_bytes(zlib.compress(json.dumps({"sources": {}}).encode('utf-8'), level=9))

    def _compute_md5(self, file_path: str) -> str:
        """Compute MD5 hash of a file"""
        md5_hash = hashlib.md5()
        with open(file_path, "rb") as f:
            for chunk in iter(lambda: f.read(4096), b""):
                md5_hash.update(chunk)
        return md5_hash.hexdigest()

    def _create_blocks(self, file_path: str) -> List[BlockMetadata]:
        """Create block metadata with content"""
        blocks = []
        with open(file_path, 'rb') as f:
            index = 0
            while True:
                data = f.read(self.block_size)
                if not data:
                    break
                try:
                    hash_value = pyssdeep.fuzzy_hash_buf(data, len(data))
                    block_data = BlockData(data, index * self.block_size)
                    blocks.append(BlockMetadata(index, self.block_size, hash_value, block_data))
                    index += 1
                except Exception as e:
                    if self.logger:
                        self.logger.warning(f"Could not compute fuzzy hash for block {index}: {str(e)}")
        return blocks

    def compute_file_metadata(self, file_path: str) -> FileMetadata:
        """Compute complete file metadata including blocks"""
        md5 = self._compute_md5(file_path)
        file_size = os.path.getsize(file_path)
        blocks = self._create_blocks(file_path)
        return FileMetadata(file_path, md5, file_size, blocks)

    def _gram_index(self) -> Dict:
        """{(block size, 7-gram): [(source, rel_path, block)], exact hash:
        [...]} over the whole database, built once per loaded database."""
        cached = self.db.get('_index')
        if cached is not None:
            return cached
        by_gram: Dict[Tuple[int, str], List] = {}
        by_hash: Dict[str, List] = {}
        for source, source_data in self.db["sources"].items():
            for rel_path, file_data in source_data["files"].items():
                for block in file_data.blocks:
                    ref = (source, rel_path, block)
                    by_hash.setdefault(block.hash, []).append(ref)
                    for key in _candidate_keys(block.hash):
                        by_gram.setdefault(key, []).append(ref)
        index = {'gram': by_gram, 'hash': by_hash}
        self.db['_index'] = index
        return index

    @staticmethod
    def _build_regions(blocks1: List[BlockMetadata], best: Dict[int, Tuple[float, BlockMetadata]]) -> Dict:
        """Group per-block best matches into contiguous regions.
        `overall_similarity` (0-100) is the mean best-match score over the
        sample's blocks: how much of the sample is found in the target.
        (It used to divide by min(len) and could exceed 100%.)"""
        matching_regions = []
        current_region = None
        overall_similarity = 0

        for i, b1 in enumerate(blocks1):
            if i not in best:
                continue
            similarity, b2 = best[i]
            if (current_region is not None and current_region.blocks > 0 and
                    b1.start_offset == current_region.source_start + current_region.length and
                    b2.start_offset == current_region.target_start + current_region.length):
                current_region.add_block(b1, b2, similarity)
            else:
                if current_region is not None and current_region.blocks > 0:
                    matching_regions.append(current_region)
                current_region = MatchingRegion()
                current_region.add_block(b1, b2, similarity)
            overall_similarity += similarity

        if current_region and current_region.blocks > 0:
            matching_regions.append(current_region)

        return {
            "overall_similarity": (overall_similarity / len(blocks1)) if blocks1 else 0,
            "matching_regions": [region.to_dict() for region in matching_regions],
            "total_regions": len(matching_regions)
        }

    def _match_against_db(self, blocks1: List[BlockMetadata]) -> Dict[Tuple[str, str], Dict]:
        """Best match per sample block for every database file that shares
        at least one candidate key. Returns {(source, rel_path): {i: (sim, block)}}."""
        index = self._gram_index()
        per_file: Dict[Tuple[str, str], Dict[int, Tuple[float, BlockMetadata]]] = {}
        for i, b1 in enumerate(blocks1):
            exact = index['hash'].get(b1.hash, ())
            for source, rel_path, b2 in exact:
                per_file.setdefault((source, rel_path), {})[i] = (100, b2)

            seen = set()
            for key in _candidate_keys(b1.hash):
                for ref in index['gram'].get(key, ()):
                    ident = id(ref[2])
                    if ident in seen:
                        continue
                    seen.add(ident)
                    file_key = (ref[0], ref[1])
                    current = per_file.get(file_key, {}).get(i)
                    if current is not None and current[0] >= 100:
                        continue
                    similarity = pyssdeep.fuzzy_compare(b1.hash, ref[2].hash)
                    if similarity > 0 and (current is None or similarity > current[0]):
                        per_file.setdefault(file_key, {})[i] = (similarity, ref[2])
        return per_file

    def find_git_root(self, path: Path) -> Optional[Tuple[str, Path]]:
        """Find Git repository information"""
        current = path
        while current != current.parent:
            if (current / '.git').is_dir():
                repo_info = GitRepoInfo(current)
                remote_url = repo_info.get_remote_url()
                if remote_url:
                    # Convert git URLs to HTTPS format if needed
                    if remote_url.startswith('git@github.com:'):
                        remote_url = f"https://github.com/{remote_url.split('git@github.com:')[1]}"
                    if remote_url.endswith('.git'):
                        remote_url = remote_url[:-4]
                    return remote_url, current
            current = current.parent
        return "Private Collection", path.parent

    def _validate_index_folder(self, folder_path: str) -> Path:
        if not folder_path or not isinstance(folder_path, str):
            raise ValueError("Folder path is required")
        folder = Path(os.path.abspath(folder_path))
        if not folder.is_dir():
            raise ValueError(f"Folder not found: {folder_path}")
        if folder.parent == folder:
            raise ValueError("Refusing to index a filesystem root; choose a specific folder")
        if self.allowed_roots and not any(
            os.path.commonpath([str(folder), root]) == root for root in self.allowed_roots
        ):
            raise ValueError(
                "Folder is outside analysis.doppelganger.db.fuzzy_allowed_roots"
            )
        return folder

    def create_db_from_folder(self, folder_path: str, extensions: List[str] = None) -> Dict:
        """Index a folder of reference binaries into the database."""
        try:
            folder = self._validate_index_folder(folder_path)

            # Provided extensions ("exe", ".DLL") or the configured ones.
            extensions_to_use = _normalize_extensions(extensions) if extensions else self.extensions

            processed = 0
            skipped = 0
            sources_found = set()
            new_entries = []

            for file_path in folder.rglob('*'):
                if not file_path.is_file():
                    continue
                if extensions_to_use and file_path.suffix.lower() not in extensions_to_use:
                    skipped += 1
                    continue
                if '.git' in file_path.parts:
                    skipped += 1
                    continue
                if processed >= self.max_index_files:
                    raise ValueError(
                        f"More than {self.max_index_files} matching files under {folder}; "
                        f"choose a narrower folder or raise fuzzy_max_files"
                    )

                try:
                    source_url, _repo_root = self.find_git_root(file_path)
                    file_metadata = self.compute_file_metadata(str(file_path))
                    rel_path = str(file_path.relative_to(folder))
                    new_entries.append((source_url, rel_path, file_metadata))
                    processed += 1
                    sources_found.add(source_url)
                    if self.logger:
                        self.logger.debug(f"Processed: {rel_path}")
                except Exception as e:
                    if self.logger:
                        self.logger.error(f"Error processing {file_path}: {str(e)}")
                    skipped += 1

            # Merge into the latest on-disk state under the lock so two
            # concurrent indexing runs don't drop each other's files.
            with _DB_LOCK:
                self.db = self._load_db()
                for source, rel_path, file_metadata in new_entries:
                    entry = self.db["sources"].setdefault(
                        source, {"files": {}, "last_updated": datetime.now().isoformat()}
                    )
                    entry["files"][rel_path] = file_metadata
                    entry["last_updated"] = datetime.now().isoformat()
                self._save_db()

            return {
                "processed": processed,
                "skipped": skipped,
                "total": processed + skipped,
                "sources": list(sources_found)
            }

        except Exception as e:
            if self.logger:
                self.logger.error(f"Database creation failed: {str(e)}")
            raise Exception(f"Database creation failed: {str(e)}")

    def analyze_files(self, file_paths: List[str], threshold: int = 1) -> List[Dict]:
        """Analyze files against the database - returns only top 3 matches per file"""
        results = []
        batch_size = 10
        
        for i in range(0, len(file_paths), batch_size):
            batch = file_paths[i:i + batch_size]
            batch_metadata = []
            
            for file_path in batch:
                try:
                    metadata = self.compute_file_metadata(file_path)
                    batch_metadata.append((file_path, metadata))
                except Exception as e:
                    if self.logger:
                        self.logger.error(f"Error processing {file_path}: {str(e)}")
                    continue
            
            for file_path, current_metadata in batch_metadata:
                matches = []
                per_file = self._match_against_db(current_metadata.blocks)
                for (source_url, rel_path), best in per_file.items():
                    file_data = self.db["sources"][source_url]["files"][rel_path]
                    comparison = self._build_regions(current_metadata.blocks, best)

                    if comparison["overall_similarity"] >= threshold:
                        matches.append({
                            "source": source_url,
                            "file": rel_path,
                            "overall_similarity": comparison["overall_similarity"],
                            "md5": file_data.md5,
                            "matching_regions": comparison["matching_regions"],
                            "total_regions": comparison["total_regions"],
                            "target_size": file_data.file_size,
                            "date_added": file_data.date_added
                        })

                # Sort matches by similarity and take top 3
                sorted_matches = sorted(matches, key=lambda x: x["overall_similarity"], reverse=True)[:3]

                result = {
                    "file": os.path.basename(file_path),
                    "path": file_path,
                    "md5": current_metadata.md5,
                    "file_size": current_metadata.file_size,
                    "total_blocks": len(current_metadata.blocks),
                    "matches": sorted_matches,  # Now contains only top 3
                    "total_matches": len(matches)  # Keep total count of all matches
                }
                results.append(result)
                
        return results

    def get_db_stats(self) -> Dict[str, Any]:
        """Get comprehensive database statistics"""
        stats = {
            "total_files": 0,
            "total_size": 0,  # Total size of indexed files
            "db_size": 0,     # Size of the database file itself
            "sources": {},
            "last_updated": None
        }
        
        # Get database file size
        try:
            stats["db_size"] = os.path.getsize(self.db_path)
            stats["db_size_human"] = self._format_size(stats["db_size"])
        except (OSError, IOError) as e:
            if self.logger:
                self.logger.error(f"Error getting database file size: {e}")
            stats["db_size"] = 0
            stats["db_size_human"] = "0 B"
        
        # Count files and sources
        for source, source_data in self.db["sources"].items():
            source_stats = {
                "file_count": len(source_data["files"]),
                "last_updated": source_data["last_updated"]
            }
            
            stats["total_files"] += source_stats["file_count"]
            for file_data in source_data["files"].values():
                stats["total_size"] += file_data.file_size
            
            stats["sources"][source] = source_stats
            
            # Track most recent update
            source_date = datetime.fromisoformat(source_data["last_updated"])
            if not stats["last_updated"] or source_date > datetime.fromisoformat(stats["last_updated"]):
                stats["last_updated"] = source_data["last_updated"]
        
        stats["total_size_human"] = self._format_size(stats["total_size"])
        
        return stats

    def _format_size(self, size: int) -> str:
        """Convert bytes to human readable format"""
        for unit in ['B', 'KB', 'MB', 'GB', 'TB']:
            if size < 1024 or unit == 'TB':
                return f"{size:.2f} {unit}"
            size /= 1024

    def print_matching_region(self, region: Dict[str, Any], source_file: str, target_file: str) -> Dict[str, Any]:
        """Generate detailed hex and ASCII comparison of matching regions"""
        comparison_data = {
            "similarity": round(region['avg_similarity'], 2),
            "length": region['length'],
            "source_file": source_file,
            "source_range": {
                "start": f"{region['source_start']:08x}",
                "end": f"{region['source_start'] + region['length']:08x}"
            },
            "target_file": target_file,
            "target_range": {
                "start": f"{region['target_start']:08x}",
                "end": f"{region['target_start'] + region['length']:08x}"
            },
            "source_data": [],
            "target_data": []
        }

        # Process source data
        for block_data in region['source_data']:
            ascii_lines = block_data['ascii_repr'].split('\n')
            hex_lines = block_data['hex_dump'].split('\n')
            for ascii_line, hex_line in zip(ascii_lines, hex_lines):
                if set(ascii_line) != {'.'}:  # Only include lines with non-dot characters
                    comparison_data["source_data"].append({
                        "ascii": ascii_line,
                        "hex": hex_line
                    })

        # Process target data
        for block_data in region['target_data']:
            ascii_lines = block_data['ascii_repr'].split('\n')
            hex_lines = block_data['hex_dump'].split('\n')
            for ascii_line, hex_line in zip(ascii_lines, hex_lines):
                if set(ascii_line) != {'.'}:  # Only include lines with non-dot characters
                    comparison_data["target_data"].append({
                        "ascii": ascii_line,
                        "hex": hex_line
                    })

        if self.logger:
            self.logger.debug(f"Processed matching region comparison for {source_file} and {target_file}")

        return comparison_data