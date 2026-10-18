# PyData theme

## The version switcher assumes root hosting

**The suspicion.** The local version entry uses `url: "/"`, which assumes the documentation is served at the origin root.

**Disposition.** The local autobuild command fits that assumption.
Read the Docs supplies hosted URLs separately, but the local base does not support an arbitrary static-site subpath.

**Targeted mitigation.** Determine whether non-root static hosting is supported.
If it is, use the actual deployment base URL instead of assuming `/`;
do not guess a deployment URL.

**Decision.** Leave `/` unchanged for now and document the assumption beside
the entry in `docs/conf.py`. The build has no deployment-base setting, and
the filesystem output directory does not identify the eventual public URL.
`docs/_static/rtd-versions.js` replaces the fallback menu with the version
URLs supplied by Read the Docs. For other static hosting under a subpath,
the fallback remains a known limitation; automatic detection is not reliable.
If that deployment needs support, an explicitly configured Sphinx
`html_baseurl` could provide the URL, but it would need to be set by the
deployer rather than inferred. No behavior change is needed for local
autobuild or the existing Read the Docs integration.
