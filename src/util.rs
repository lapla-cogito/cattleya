pub struct RecursiveDir {
    root: Box<dyn Iterator<Item = std::io::Result<std::fs::DirEntry>>>,
    children: Box<dyn Iterator<Item = RecursiveDir>>,
}

impl RecursiveDir {
    pub fn new<P: AsRef<std::path::Path>>(path: P) -> std::io::Result<Self> {
        let root = Box::new(std::fs::read_dir(&path)?);
        let children = Box::new(std::fs::read_dir(&path)?.filter_map(|e| {
            let e = e.ok()?;
            if e.file_type().ok()?.is_dir() {
                return RecursiveDir::new(e.path()).ok();
            }
            None
        }));
        Ok(RecursiveDir { root, children })
    }

    pub fn entries(self) -> Box<dyn Iterator<Item = std::io::Result<std::fs::DirEntry>>> {
        Box::new(self.root.chain(self.children.flat_map(|s| s.entries())))
    }
}

impl Iterator for RecursiveDir {
    type Item = std::io::Result<std::fs::DirEntry>;
    fn next(&mut self) -> Option<Self::Item> {
        if let Some(item) = self.root.next() {
            return Some(item);
        }
        if let Some(child) = self.children.next() {
            self.root = child.entries();
            return self.next();
        }
        None
    }
}
