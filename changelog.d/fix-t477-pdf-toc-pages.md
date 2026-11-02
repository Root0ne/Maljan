### Fixed

- **The PDF's contents page prints the page each section starts on (T-477).** Every contents entry printed "0": the entry is a flex row, and the PDF engine leaves a page reference inside a flex item unresolved. The PDF now lays each entry out as a block with its page number floated right, the same row on paper, through a print correction it applies on top of the report's own stylesheet, so the HTML export is byte for byte what it was.
