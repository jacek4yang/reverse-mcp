fn main() -> Result<(), Box<dyn std::error::Error>> {
    let (_, ida_path, idalib_path) = idalib94_build::idalib_install_paths_with(false);
    if !ida_path.exists() || !idalib_path.exists() {
        idalib94_build::configure_idasdk_linkage();
    } else {
        idalib94_build::configure_linkage()?;
    }
    Ok(())
}
