#!/usr/bin/env python3
"""Fast native prompt intake; other lifecycle work is loaded only when needed."""

def __getattr__(name):
    # Keep the established import API without eagerly importing SQLite/HTTP helpers.
    if name in ('Dispatcher', 'invocation_context'):
        from babel import lifecycle_dispatcher
        return getattr(lifecycle_dispatcher, name)
    raise AttributeError(name)


def main():
    import sys
    options = {}
    args = iter(sys.argv[1:])
    try:
        for arg in args:
            key, sep, value = arg.partition('=')
            if key not in ('--client', '--account-file') or key in options:
                raise ValueError
            options[key] = value if sep else next(args)
    except (ValueError, StopIteration):
        options = {}
    if set(options) != {'--client', '--account-file'} or options['--client'] != 'claude':
        from babel.lifecycle_dispatcher import main as dispatch_main
        return dispatch_main()
    import json
    raw = sys.stdin.buffer.read(65537)
    try:
        if len(raw) > 65536:
            raise ValueError('Native hook input too large')
        data = json.loads(raw)
        if isinstance(data, dict) and data.get('hook_event_name') == 'UserPromptSubmit':
            from babel.prompt_intake import submit, REPORTING_HINT
            result = submit(options['--account-file'], data)
            if result.get('reporting_hint'):
                print(json.dumps({'hookSpecificOutput': {'hookEventName': 'UserPromptSubmit', 'additionalContext': REPORTING_HINT}}))
            else:
                print('{}')
            return
    except (OSError, ValueError, KeyError):
        print('{}')
        print('Babel lifecycle hook unavailable; existing task continues, pending evidence retained.', file=sys.stderr)
        return
    from babel.lifecycle_dispatcher import main as dispatch_main
    return dispatch_main(raw=raw)


if __name__ == '__main__':
    main()
