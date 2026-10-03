import os
import sys
import ctypes
import argparse
import ipaddress

# Config paths (Uploads, Results, Scanners\..., Utils\...) are relative to
# the repository. An elevated shell usually starts in C:\Windows\System32,
# so anchor the working directory before anything resolves them.
os.chdir(os.path.dirname(os.path.abspath(__file__)))

from app import create_app, setup_logging  # noqa: E402


def is_running_as_admin():
    """Check if the script is running with administrative privileges."""
    try:
        return ctypes.windll.shell32.IsUserAnAdmin() != 0
    except AttributeError:
        return os.geteuid() == 0


def is_loopback(host):
    if host in ('localhost', ''):
        return host == 'localhost'
    try:
        return ipaddress.ip_address(host).is_loopback
    except ValueError:
        return False


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--debug', action='store_true',
                        help='Flask debug mode: interactive debugger + auto-reload (loopback only). Implies --verbose.')
    parser.add_argument('--verbose', action='store_true', help='Verbose (DEBUG-level) logging')
    parser.add_argument('--ip', type=str, help='Specify host IP address (e.g., --ip 192.168.1.120)')
    args = parser.parse_args()

    if not is_running_as_admin():
        print("[!] This script requires administrative privileges. Please run as administrator.")
        sys.exit(1)

    # Only the Werkzeug reloader's child serves requests; don't start
    # background pollers in its parent as well.
    reloader_parent = args.debug and os.environ.get('WERKZEUG_RUN_MAIN') != 'true'
    app = create_app(start_background=not reloader_parent)

    # Set host IP if provided
    if args.ip:
        app.config['application']['host'] = args.ip
        print(f"[+] Host IP set to: {args.ip}")
    host = app.config['application']['host']

    debug = args.debug or bool(app.config['application'].get('debug'))
    if debug and not is_loopback(host):
        print(f"[!] Refusing to enable debug mode on non-loopback address {host}: "
              "the Werkzeug debugger must not be reachable from the network. "
              "Use --verbose for detailed logs instead.")
        sys.exit(1)
    if not is_loopback(host):
        print(f"[!] Listening on {host}: anyone who can reach this address can upload and "
              "execute samples on this machine (there is no authentication). "
              "Restrict access with a firewall rule.")

    app.config['DEBUG'] = debug
    app.config['application']['debug'] = debug
    app.config['VERBOSE'] = debug or args.verbose

    # Set up logging based on the debug / verbose flags
    setup_logging(app)

    # Run the app
    app.run(
        host=host,
        port=app.config['application']['port'],
        debug=debug,
    )


if __name__ == '__main__':
    main()
