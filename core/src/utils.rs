use crate::prelude::*;

/// Implements [`Debug`] from the [`Display`] implementation of `value`.
///
/// Can be used to give fields a arbitrary [`mod@str`] without surrounding quotes,
/// for example in [`fmt::DebugStruct::field`].
pub struct CleanDebug<'a, T: ?Sized + Display>(&'a T);
impl<'a, T: ?Sized + Display> CleanDebug<'a, T> {
    /// Creates a new wrapper around `value` with [`Debug`] implemented as [`Display`].
    #[inline]
    pub fn new(value: &'a T) -> Self {
        Self(value)
    }
}
impl<'a, T: ?Sized + Display> Debug for CleanDebug<'a, T> {
    #[inline]
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        Display::fmt(self.0, f)
    }
}
impl<'a, T: ?Sized + Display> Display for CleanDebug<'a, T> {
    #[inline]
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        Display::fmt(self.0, f)
    }
}
/// Trait to enable `.as_clean` to get a [`CleanDebug`] for the variable.
pub trait AsCleanDebug {
    /// Get a [`CleanDebug`] for Self.
    ///
    /// # Examples
    ///
    /// ```
    /// # use kvarn::prelude::*;
    /// let s = "a\tstring";
    /// let clean_debug = s.as_clean();
    ///
    /// // A debug formatting is the same as the value itself.
    /// assert_eq!(format!("{:?}", clean_debug), s);
    ///
    /// // The debug formatting of the `&str` is messy for clean output in debug implementations.
    /// assert_eq!(format!("{:?}", s), r#""a\tstring""#)
    /// ```
    fn as_clean(&self) -> CleanDebug<Self>
    where
        Self: Display,
    {
        CleanDebug::new(self)
    }
}
impl<T: Display + ?Sized> AsCleanDebug for T {}
