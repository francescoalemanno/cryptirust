pub fn list() -> Vec<String> {
    let libr = vec!["abus", "acum", "adcen", "aealc", "afide", "agit"];
    return libr.iter().map(|x| x.to_string()).collect();
}
