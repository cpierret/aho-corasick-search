# Contributing

Thanks for helping improve Aho-Corasick Search. This project is small, so
changes should stay focused, easy to review, and compatible with the existing
GPLv2 license.

## License

All contributions must remain under GNU General Public License version 2
(GPLv2). Do not add files with conflicting license terms. If a contribution is
derived from another project, include the required attribution and confirm that
the source license is compatible with GPLv2.

## Development Workflow

1. Make one logical change at a time.
2. Preserve the existing public API unless the change explicitly requires an
   incompatible update.
3. Update tests for behavioral changes.
4. Update `README.md` and Doxygen comments when public behavior or API usage
   changes.
5. Keep generated files out of commits, including `build*/` directories and
   `docs/api/`.

## Build And Test

Use CMake for normal development:

```sh
cmake -S . -B build -DBUILD_TESTS=ON -DBUILD_EXAMPLES=ON -DENABLE_ASAN=ON
cmake --build build
ctest --test-dir build --output-on-failure
```

Coverage reports can be generated with GCC or Clang:

```sh
cmake -S . -B build-coverage -DBUILD_TESTS=ON -DENABLE_COVERAGE=ON
cmake --build build-coverage --target coverage
```

Generated coverage files are written under `build-coverage/coverage/`.

## API Documentation

Install Doxygen, configure the project, then build the `docs` target:

```sh
cmake -S . -B build -DBUILD_DOCS=ON
cmake --build build --target docs
```

The generated HTML documentation is written to `docs/api/html/`.

## C++ Guidelines

- The project currently targets C++17.
- Prefer standard library containers and RAII for new code.
- Keep ownership and lifetime rules explicit.
- Avoid raw `new` and `delete` in new code.
- Keep comments concise and focused on non-obvious behavior.
- Validate input at API boundaries and keep failure modes explicit.

## Test Expectations

Add or update tests for:

- Pattern insertion and compilation behavior.
- Case-sensitive, case-insensitive, and per-pattern matching.
- Failure-state transitions and overlapping matches.
- Streaming searches split across buffers.
- Error paths such as empty patterns and invalid options.

## Security And Dependencies

Treat search input and CLI arguments as untrusted. Avoid unsafe parsing,
unchecked buffer operations, and unnecessary dependencies. New dependencies
should be mature, maintained, and justified by a clear benefit.
