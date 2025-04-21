pub(crate) fn single<T>(values: impl IntoIterator<Item = T>) -> Option<T> {
    let mut iter = values.into_iter();
    iter.next().filter(|_| iter.next().is_none())
}

pub(crate) fn pair<T>(values: impl IntoIterator<Item = T>) -> Option<(T, T)> {
    let mut iter = values.into_iter();
    let first = iter.next()?;
    let second = iter.next().filter(|_| iter.next().is_none())?;
    Some((first, second))
}
