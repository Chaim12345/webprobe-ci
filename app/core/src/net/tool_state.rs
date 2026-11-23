//! Type-erased per-Shared state for tools net does not know. A tool stores
//! its own state value under its Rust type, so `Shared` hosts the slot
//! without naming the tool's types (keeps net free of tool-module edges).

use std::any::{Any, TypeId};
use std::collections::HashMap;

use crate::sync::Mutex;

/// A bag of tool-owned states, one value per tool state type.
pub struct ToolState {
    map: Mutex<HashMap<TypeId, Box<dyn Any + Send + Sync>>>,
}

impl Default for ToolState {
    fn default() -> Self {
        Self::new()
    }
}

impl ToolState {
    pub fn new() -> Self {
        ToolState {
            map: Mutex::new(HashMap::new()),
        }
    }

    /// A copy of the tool state of type `T`, when the tool stored one.
    pub fn get<T: Any + Send + Sync + Clone>(&self) -> Option<T> {
        self.map
            .lock()
            .unwrap()
            .get(&TypeId::of::<T>())
            .and_then(|b| b.downcast_ref::<T>())
            .cloned()
    }

    /// The tool state of type `T`, storing `T::default()` on first use.
    pub fn get_or_insert<T: Any + Send + Sync + Clone + Default>(&self) -> T {
        self.map
            .lock()
            .unwrap()
            .entry(TypeId::of::<T>())
            .or_insert_with(|| Box::new(T::default()))
            .downcast_ref::<T>()
            .expect("slot type is keyed by TypeId")
            .clone()
    }

    /// Store (or replace) the tool state of type `T`.
    pub fn insert<T: Any + Send + Sync>(&self, v: T) {
        self.map
            .lock()
            .unwrap()
            .insert(TypeId::of::<T>(), Box::new(v));
    }
}
