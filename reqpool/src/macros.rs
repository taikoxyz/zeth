/// This macro implements the Display trait for a type by using serde_json's pretty printing.
/// If the type cannot be serialized to JSON, it falls back to using Debug formatting.
///
/// # Example
///
/// ```rust
/// use serde::{Serialize, Deserialize};
///
/// #[derive(Debug, Serialize, Deserialize)]
/// struct Person {
///     name: String,
///     age: u32
/// }
///
/// impl_display_using_json_pretty!(Person);
///
/// let person = Person {
///     name: "John".to_string(),
///     age: 30
/// };
///
/// // Will print:
/// // {
/// //   "name": "John",
/// //   "age": 30
/// // }
/// println!("{}", person);
/// ```
///
/// The type must implement serde's Serialize trait for JSON serialization to work.
/// If serialization fails, it will fall back to using the Debug implementation.
#[macro_export]
macro_rules! impl_display_using_json_pretty {
    ($type:ty) => {
        impl std::fmt::Display for $type {
            fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                match serde_json::to_string_pretty(self) {
                    Ok(s) => write!(f, "{}", s),
                    Err(_) => write!(f, "{:?}", self),
                }
            }
        }
    };
}
