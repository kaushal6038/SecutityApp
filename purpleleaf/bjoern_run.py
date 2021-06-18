import argparse
import bjoern
import importlib
import os


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('app', help='wsgi application to serve.')
    parser.add_argument('--env', action='append',
                        help='environment variable to set.')
    parser.add_argument('--bind', help='socket to bind to.')
    args = parser.parse_args()

    for e in args.env:
        name, value = e.split('=')
        os.putenv(name, value)

    module, app = args.app.split(':')
    app = getattr(importlib.import_module(module), app)

    host, port = args.bind.split(':')
    bjoern.run(app, host, int(port))


if __name__ == '__main__':
    main()
