# CarrollUniversityCS.github.io

The research projects hub for the Department of Computer Science at Carroll University,
served at https://carrolluniversitycs.github.io/.

Each project lives in its own repository under this organization and publishes its own
GitHub Pages site at `https://carrolluniversitycs.github.io/<repo>/`. This repository
holds only the hub page, `index.html`, a plain static page with no build step.

## Add a project

1. Put the project in a public repository under `CarrollUniversityCS`.
2. Turn on GitHub Pages for it (Settings, Pages).
3. Open a pull request here that copies one `<li class="project">` block in `index.html`
   and fills in the title, status, one-paragraph summary, meta line and links.

Project pages are research outputs of individual faculty and students, not official
statements of Carroll University. Maintainer: Jack Forden (jforden@carrollu.edu).

## Where this copy lives

These files are kept in `CarrollUniversityCS/patch-watch` under `hub/` until the
`CarrollUniversityCS.github.io` repository exists. Copy `index.html`, `README.md` and
`.nojekyll` to the root of that repository, then set Settings, Pages, to deploy from
branch `main`, folder `/ (root)`. The patch-watch Pages workflow does not publish `hub/`.
