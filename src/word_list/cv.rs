pub fn list() -> Vec<String> {
    let consonants = "qwrtpsdfgjklzxcvbnm";
    let vowels = "aeiou";
    let mut lst = Vec::new();
    for c in consonants.chars() {
        for v in vowels.chars() {
            lst.push(c.to_string() + &v.to_string());
            lst.push(v.to_string() + &c.to_string());
        }
    }
    return lst;
}
