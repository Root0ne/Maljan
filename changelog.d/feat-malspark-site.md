### Added

- **The public site is Malspark, with a home page of its own.** The project's public name is now Malspark; the code keeps the name `maljan` (the Python package, the `maljan` command, the environment variables and the repository). The docs site gains a home page at `/` that says what the framework does, and the docs move under `/docs/`. Every page carries its own title, description and canonical address on https://malspark.com, Open Graph and Twitter cards with a generated card image, and JSON-LD (the software, the project and the site on the home page, a breadcrumb trail on each docs page); the build writes `sitemap.xml` and `robots.txt` and ships a favicon set drawn from the logo. The site is set in one monospace family on the brand navy, with the logo's blues and amber as its accents.

### Changed

- **The docs live under `/docs/`, and the site's path is a build setting.** `NEXT_PUBLIC_BASE_PATH` sets the path the site is served under: unset for the domain's root, `/Maljan` for the GitHub Pages build, which the docs workflow still makes. Every docs address the site served at the root, from the MkDocs era or after, now leads to the same page under `/docs/`, anchor included. The validation-code register links its pages under `/docs/`.
