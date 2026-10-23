//! Storage vocabulary for the single semantic-tree construction kernel.

use std::{
    fmt::Debug,
    ops::{Deref, DerefMut},
};

use super::ParseError;

#[cfg(feature = "xmldsig")]
mod lexical;
pub(crate) mod names;

/// Internal storage specialization; not an independent XML policy surface.
#[doc(hidden)]
pub trait Storage:
    Copy + Debug + crate::xml_input::lexical::storage::Storage<Label = Self::Text>
{
    type Text: AsRef<str> + Deref<Target = str> + Debug + std::fmt::Display;
    type FrozenText: AsRef<str> + Deref<Target = str> + Debug + std::fmt::Display;
    type Values<T>: Values<T>;
    type Declarations<'input>: super::preflight::Declarations<'input, Self>;
    type ParseFailure: From<ParseError>;

    fn lexical_error(
        error: crate::xml_input::lexical::Error<Self::Text, Self::Refusal>,
    ) -> Self::ParseFailure;

    fn values<T>(&self, capacity: usize) -> Result<Self::Values<T>, ParseError>;
    fn declarations<'input>(&self) -> Self::Declarations<'input>;
    fn text(&self, value: &str) -> Result<Self::Text, ParseError>;
    fn freeze(value: Self::Text) -> Self::FrozenText;
    fn formatted(&self, arguments: std::fmt::Arguments<'_>) -> Result<Self::Text, ParseError> {
        let mut text = self.text("")?;
        self.format_into(&mut text, arguments)?;
        Ok(text)
    }
    fn format_into(
        &self,
        text: &mut Self::Text,
        arguments: std::fmt::Arguments<'_>,
    ) -> Result<(), ParseError> {
        struct Writer<'a, S: Storage> {
            storage: S,
            text: &'a mut S::Text,
            failure: Option<ParseError>,
        }
        impl<S: Storage> std::fmt::Write for Writer<'_, S> {
            fn write_str(&mut self, value: &str) -> std::fmt::Result {
                if self.failure.is_some() {
                    return Err(std::fmt::Error);
                }
                match self.storage.append(self.text, value) {
                    Ok(()) => Ok(()),
                    Err(error) => {
                        self.failure = Some(error);
                        Err(std::fmt::Error)
                    }
                }
            }
        }
        let mut writer = Writer {
            storage: *self,
            text,
            failure: None,
        };
        let result = std::fmt::write(&mut writer, arguments);
        if let Some(error) = writer.failure {
            return Err(error);
        }
        result.expect("XML diagnostics use only infallible scalar and string formatting");
        Ok(())
    }
    fn optional_text(&self, value: Option<&str>) -> Result<Option<Self::Text>, ParseError> {
        value.map(|value| self.text(value)).transpose()
    }
    fn append(&self, target: &mut Self::Text, value: &str) -> Result<(), ParseError>;
    fn reserve_text(&self, target: &mut Self::Text, additional: usize) -> Result<(), ParseError>;
    fn normalize_id(&self, value: &mut Self::Text) -> Result<(), ParseError>;
    fn finish_bytes(&self, bytes: Self::Values<u8>) -> Result<Self::Text, ParseError>;
    fn charge(&self, work: usize) -> Result<(), ParseError>;
    fn finish_values<T>(&self, values: &mut Self::Values<T>);
}

#[doc(hidden)]
pub trait Values<T>: Deref<Target = [T]> + DerefMut + IntoIterator<Item = T> {
    fn push(&mut self, value: T) -> Result<(), ParseError>;
    fn pop(&mut self) -> Option<T>;
    fn clear(&mut self);
    fn drain_all(
        &mut self,
    ) -> Result<
        impl DoubleEndedIterator<Item = T> + ExactSizeIterator + std::iter::FusedIterator + '_,
        ParseError,
    >;
    fn extend_copy(&mut self, values: &[T]) -> Result<(), ParseError>
    where
        T: Copy;
    #[cfg(feature = "xml-backend-roxmltree")]
    fn insert_copy(&mut self, index: usize, value: T) -> Result<(), ParseError>
    where
        T: Copy,
    {
        let old_length = self.len();
        self.push(value)?;
        self.copy_within(index..old_length, index + 1);
        self[index] = value;
        Ok(())
    }
}

#[doc(hidden)]
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Native;

impl crate::xml_input::lexical::storage::Storage for Native {
    type Label = String;
    type Refusal = std::collections::TryReserveError;
    type Attributes<'a> = Vec<crate::xml_input::lexical::Attribute<'a>>;

    fn attributes<'a>(&self) -> Self::Attributes<'a> {
        Vec::new()
    }
    fn admit(&self, _: usize) -> Result<(), Self::Refusal> {
        Ok(())
    }
    fn qualified_name(
        &self,
        name: crate::xml_input::lexical::Name<'_>,
    ) -> Result<String, Self::Refusal> {
        crate::xml_input::lexical::storage::Native.qualified_name(name)
    }
}

impl<T> Values<T> for Vec<T> {
    fn drain_all(
        &mut self,
    ) -> Result<
        impl DoubleEndedIterator<Item = T> + ExactSizeIterator + std::iter::FusedIterator + '_,
        ParseError,
    > {
        Ok(self.drain(..))
    }
    fn extend_copy(&mut self, values: &[T]) -> Result<(), ParseError>
    where
        T: Copy,
    {
        self.try_reserve(values.len())
            .map_err(|_| ParseError::AllocationFailed)?;
        self.extend_from_slice(values);
        Ok(())
    }
    fn clear(&mut self) {
        Vec::clear(self);
    }
    fn pop(&mut self) -> Option<T> {
        Vec::pop(self)
    }
    fn push(&mut self, value: T) -> Result<(), ParseError> {
        self.try_reserve(1)
            .map_err(|_| ParseError::AllocationFailed)?;
        Vec::push(self, value);
        Ok(())
    }
}

impl Storage for Native {
    type Text = String;
    type FrozenText = String;
    type Values<T> = Vec<T>;
    type Declarations<'input> = std::collections::HashMap<
        super::preflight::DtdAttributeName<'input>,
        super::preflight::DtdAttributeInfo,
    >;
    type ParseFailure = ParseError;

    fn lexical_error(error: crate::xml_input::lexical::Error) -> ParseError {
        match error {
            crate::xml_input::lexical::Error::Resource(_) => ParseError::AllocationFailed,
            error => ParseError::Backend {
                backend: "xml-preflight",
                message: error.to_string(),
            },
        }
    }

    fn declarations<'input>(&self) -> Self::Declarations<'input> {
        std::collections::HashMap::new()
    }
    fn freeze(value: String) -> String {
        value
    }

    fn values<T>(&self, capacity: usize) -> Result<Vec<T>, ParseError> {
        let mut values = Vec::new();
        values
            .try_reserve_exact(capacity)
            .map_err(|_| ParseError::AllocationFailed)?;
        Ok(values)
    }
    fn text(&self, value: &str) -> Result<String, ParseError> {
        let mut text = String::new();
        text.try_reserve_exact(value.len())
            .map_err(|_| ParseError::AllocationFailed)?;
        text.push_str(value);
        Ok(text)
    }
    fn append(&self, target: &mut String, value: &str) -> Result<(), ParseError> {
        target
            .try_reserve(value.len())
            .map_err(|_| ParseError::AllocationFailed)?;
        target.push_str(value);
        Ok(())
    }
    fn reserve_text(&self, target: &mut String, additional: usize) -> Result<(), ParseError> {
        target
            .try_reserve_exact(additional)
            .map_err(|_| ParseError::AllocationFailed)
    }
    fn normalize_id(&self, value: &mut String) -> Result<(), ParseError> {
        let mut previous_space = true;
        value.retain(|character| {
            let space = character == ' ';
            let retain = !space || !previous_space;
            previous_space = space;
            retain
        });
        if value.ends_with(' ') {
            value.pop();
        }
        Ok(())
    }
    fn finish_bytes(&self, bytes: Vec<u8>) -> Result<String, ParseError> {
        Ok(String::from_utf8(bytes).expect("XML normalization preserves complete UTF-8 sequences"))
    }
    fn charge(&self, _: usize) -> Result<(), ParseError> {
        Ok(())
    }
    fn finish_values<T>(&self, values: &mut Vec<T>) {
        values.shrink_to_fit();
    }
}

#[cfg(feature = "xmldsig")]
#[derive(Clone)]
pub(crate) struct Accounted<'w, W: structured_asn1::memory::Work>(pub &'w W);

#[cfg(feature = "xmldsig")]
impl<W: structured_asn1::memory::Work> Copy for Accounted<'_, W> {}
#[cfg(feature = "xmldsig")]
impl<W: structured_asn1::memory::Work> Debug for Accounted<'_, W> {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("AccountedXmlStorage")
    }
}
#[cfg(feature = "xmldsig")]
impl<W: structured_asn1::memory::Work> Storage for Accounted<'_, W> {
    type Text = structured_asn1::memory::OwnedText<W>;
    type FrozenText = structured_asn1::memory::OwnedText;
    type Values<T> = structured_asn1::memory::OwnedVec<T, W>;
    type Declarations<'input> = structured_asn1::memory::OwnedMap<
        super::preflight::DtdAttributeName<'input>,
        super::preflight::DtdAttributeInfo,
        W,
    >;
    type ParseFailure = super::AccountedParseError;

    fn lexical_error(
        error: crate::xml_input::lexical::Error<Self::Text, Self::Refusal>,
    ) -> Self::ParseFailure {
        match error {
            crate::xml_input::lexical::Error::Resource(error) => {
                ParseError::SharedExecution(error).into()
            }
            error => super::AccountedParseError::Lexical(
                error.map_label(structured_asn1::memory::OwnedText::into_owned),
            ),
        }
    }

    fn declarations<'input>(&self) -> Self::Declarations<'input> {
        self.0.map()
    }
    fn freeze(value: Self::Text) -> Self::FrozenText {
        value.into_owned()
    }

    fn values<T>(&self, capacity: usize) -> Result<Self::Values<T>, ParseError> {
        let mut values = self.0.vector();
        values.try_reserve_exact(capacity)?;
        Ok(values)
    }
    fn text(&self, value: &str) -> Result<Self::Text, ParseError> {
        Ok(structured_asn1::memory::OwnedText::try_from_str(
            value, self.0,
        )?)
    }
    fn append(&self, target: &mut Self::Text, value: &str) -> Result<(), ParseError> {
        Ok(target.try_push_str(value)?)
    }
    fn reserve_text(&self, target: &mut Self::Text, additional: usize) -> Result<(), ParseError> {
        Ok(target.try_reserve_exact(additional)?)
    }
    fn normalize_id(&self, value: &mut Self::Text) -> Result<(), ParseError> {
        self.charge(value.len())?;
        let empty = self.text("")?;
        let mut bytes = std::mem::replace(value, empty).into_bytes();
        let mut output = 0;
        let mut previous_space = true;
        for index in 0..bytes.len() {
            let byte = bytes[index];
            let space = byte == b' ';
            if !space || !previous_space {
                bytes[output] = byte;
                output += 1;
            }
            previous_space = space;
        }
        if output != 0 && bytes[output - 1] == b' ' {
            output -= 1;
        }
        self.charge(bytes.len() - output)?;
        while bytes.len() > output {
            bytes.pop();
        }
        *value = finish(bytes)?;
        Ok(())
    }
    fn finish_bytes(&self, bytes: Self::Values<u8>) -> Result<Self::Text, ParseError> {
        finish(bytes)
    }
    fn charge(&self, work: usize) -> Result<(), ParseError> {
        self.0.charge_work(
            u64::try_from(work).map_err(|_| structured_asn1::memory::MemoryError::WorkExceeded)?,
        )?;
        Ok(())
    }
    fn finish_values<T>(&self, _: &mut Self::Values<T>) {
        // Retain the already-admitted allocation. A fresh allocation merely
        // to trim a completed vector would increase construction's peak.
    }
}

#[cfg(feature = "xmldsig")]
fn finish<W: structured_asn1::memory::Work>(
    bytes: structured_asn1::memory::OwnedVec<u8, W>,
) -> Result<structured_asn1::memory::OwnedText<W>, ParseError> {
    use structured_asn1::memory::{OwnedText, TextErrorKind};
    OwnedText::from_utf8(bytes).map_err(|error| match error.kind() {
        TextErrorKind::Resource(error) => ParseError::SharedExecution(error),
        TextErrorKind::Utf8(_) => unreachable!("XML normalization preserves UTF-8 boundaries"),
    })
}

#[cfg(feature = "xmldsig")]
impl<T, W: structured_asn1::memory::Work> Values<T> for structured_asn1::memory::OwnedVec<T, W> {
    fn drain_all(
        &mut self,
    ) -> Result<
        impl DoubleEndedIterator<Item = T> + ExactSizeIterator + std::iter::FusedIterator + '_,
        ParseError,
    > {
        Ok(self.try_drain_all()?)
    }
    fn extend_copy(&mut self, values: &[T]) -> Result<(), ParseError>
    where
        T: Copy,
    {
        Ok(self.try_extend_from_slice(values)?)
    }
    fn clear(&mut self) {
        structured_asn1::memory::OwnedVec::clear(self);
    }
    fn push(&mut self, value: T) -> Result<(), ParseError> {
        Ok(self.try_push(value)?)
    }
    fn pop(&mut self) -> Option<T> {
        structured_asn1::memory::OwnedVec::pop(self)
    }
}
