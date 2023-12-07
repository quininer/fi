use std::path::Path;


pub fn hashname(path: &Path) -> String {
    use std::hash::{ Hash, Hasher };
    use std::collections::hash_map::DefaultHasher;

    let mut hasher = DefaultHasher::new();
    std::process::id().hash(&mut hasher);
    std::time::SystemTime::now().hash(&mut hasher);
    path.as_os_str().len().hash(&mut hasher);
    path.hash(&mut hasher);
    let out = hasher.finish();

    data_encoding::HEXLOWER.encode(&out.to_le_bytes())
}
