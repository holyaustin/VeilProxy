//! PyO3 bindings. The master key never crosses into Python: `KeyHolder` keeps it
//! inside Rust-owned, zeroize-on-drop memory and only exposes operations.

pub mod core;

#[cfg(feature = "python")]
mod py {
    use super::core;
    use pyo3::exceptions::PyValueError;
    use pyo3::prelude::*;
    use pyo3::types::PyBytes;

    fn err(e: String) -> PyErr {
        PyValueError::new_err(e)
    }

    #[pyclass(name = "KeyHolder")]
    pub struct KeyHolder {
        inner: core::Vault,
    }

    #[pymethods]
    impl KeyHolder {
        #[new]
        fn new() -> Self {
            Self { inner: core::Vault::new() }
        }
        fn is_unlocked(&self) -> bool {
            self.inner.is_unlocked()
        }
        fn unlock(&mut self, shares: Vec<String>, key_check: &str) -> PyResult<bool> {
            self.inner.unlock(&shares, key_check).map_err(err)
        }
        fn lock(&mut self) {
            self.inner.lock();
        }
        fn encrypt<'py>(
            &self,
            py: Python<'py>,
            session: &str,
            plaintext: &[u8],
            aad: &[u8],
        ) -> PyResult<Bound<'py, PyBytes>> {
            let out = self.inner.seal(session, plaintext, aad).map_err(err)?;
            Ok(PyBytes::new_bound(py, &out))
        }
        fn decrypt<'py>(
            &self,
            py: Python<'py>,
            session: &str,
            blob: &[u8],
            aad: &[u8],
        ) -> PyResult<Bound<'py, PyBytes>> {
            let out = self.inner.open(session, blob, aad).map_err(err)?;
            Ok(PyBytes::new_bound(py, &out))
        }
        fn tag(&self, session: &str, data: &[u8]) -> PyResult<String> {
            self.inner.tag(session, data).map_err(err)
        }
    }

    /// Returns (shares, key_check). The master key is wiped before returning.
    #[pyfunction]
    fn generate_shares(n: u8, k: u8) -> PyResult<(Vec<String>, String)> {
        core::generate(n, k).map_err(err)
    }

    /// Utility/testing: split arbitrary bytes.
    #[pyfunction]
    fn split_secret(secret: &[u8], n: u8, k: u8) -> PyResult<Vec<String>> {
        let sh = core::split(secret, n, k).map_err(err)?;
        Ok(sh.iter().map(core::encode_share).collect())
    }

    /// Utility/testing: recombine shares into bytes (the gateway never calls this).
    #[pyfunction]
    fn combine_shares<'py>(py: Python<'py>, shares: Vec<String>) -> PyResult<Bound<'py, PyBytes>> {
        let out = core::combine_strings(&shares).map_err(err)?;
        Ok(PyBytes::new_bound(py, &out))
    }

    #[pymodule]
    fn veil_core(m: &Bound<'_, PyModule>) -> PyResult<()> {
        m.add_class::<KeyHolder>()?;
        m.add_function(wrap_pyfunction!(generate_shares, m)?)?;
        m.add_function(wrap_pyfunction!(split_secret, m)?)?;
        m.add_function(wrap_pyfunction!(combine_shares, m)?)?;
        m.add("__version__", env!("CARGO_PKG_VERSION"))?;
        Ok(())
    }
}
