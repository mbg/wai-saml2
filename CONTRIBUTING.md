# Contributing

Thank you for your interest in this library! All contributions to this library are welcome and will be reviewed as soon as possible.

## Guidelines for pull requests

These guidelines are intended to help contributors do the right thing when making changes and to avoid them having to rewrite code at a later point. Do not worry about getting things wrong at first though, since issues can always be addressed in the code review. If you have any questions, feel free to ask as part of the pull request or open an issue.

Try to stick to one improvement, fix, new feature, etc. per pull request. Several pull requests are preferred over one which tries to do multiple things.

### Style

Do not worry about code style too much, but try to stick to existing code style where possible. Maintain the same amount of indentation (4 spaces) and try to keep to a limit of 80 characters per line. Where there is a particular way of formatting the code used elsewhere in the project, that same formatting should be applied to new code. There are no real preferences for the layout of expressions _within_ definitions as long as the code is readable.

### Dependencies

It is preferable not to add any new dependencies unless absolutely necessary. If adding a new dependency is required, add as broad as possible version bounds for it in `package.yaml`. As part of the pull request, please explain why the new dependency is needed.

### Documentation

All changes should be well documented in line with the existing parts of the library and should at least have Haddock comments (_including_ definitions that are not exported). If making changes to the public interface of a module, use `@since` annotations to indicate the version that introduces them. Adding examples to either the Haddock comments or the README is encouraged. For more complex definitions (such as e.g. `validateResponse`), line-level comments are appreciated.

- Each module should have a Haddock comment describing the overall purpose of the module.
- Data types should have Haddock comments for the type, constructors, and record fields (if applicable). All Haddock comments should precede the respective definition on a previous line (i.e. using `-- |`). _Never_ use Haddock comments that follow a definition on a subsequent (i.e. `-- ^`). For function or constructor parameters, the latter may be used provided that the comment starts on the same line as the parameter.

### Versioning

This package follows the [Haskell Package Versioning Policy](https://pvp.haskell.org).

### Changelog

Update the top of `CHANGELOG.md` with a section for the new version and a list of bullet points documenting your changes (documentation changes do not need to be documented in the changelog). If your change does not require a bump of the version number, just add a section titled "Unreleased".

## Release process (Write-access required)

This documents the release process for the `wai-saml2` library.

1. [Compare](https://github.com/mbg/wai-saml2/compare/wai-saml2-0.6...main) the changes in `main` to the latest release tag.
1. Identify and address any missing `@since` annotations, missing comments, etc.
1. Bump the version in `package.yaml` and re-generate the `.cabal` file.
1. Ensure that `CHANGELOG.md` does not contain an "Unreleased" section and reflects the `package.yaml` version.
1. Tag the commit with `wai-saml2-[version]` and push the tags.
1. This should automatically start a dry run of the [release workflow](https://github.com/mbg/wai-saml2/actions/workflows/hackage.yml). Check that this succeeds and there are no issues in the workflow log that should be addressed before proceeding.
1. Create a new release for the release tag.
1. Publish the release. This will automatically start the [release workflow](https://github.com/mbg/wai-saml2/actions/workflows/hackage.yml). There is a 1 minute gate at the start during which the workflow can be stopped before it proceeds.
1. The release workflow will upload the new package version as a release candidate on Hackage. If all is good, publish the release candidate on Hackage.
