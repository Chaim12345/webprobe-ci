//! Where net gets the active extension hooks. The extension host implements
//! this trait and `Shared` stores it as a trait object, so the proxy never
//! names the host type (keeps net free of the ext_host module edge).

use std::any::Any;
use std::sync::Arc;

use webprobe_support::ext::ProxyHooks;

/// A source of the enabled extensions' proxy hooks.
pub trait ExtHookSource: Send + Sync {
    /// The enabled extensions' hooks, in host order.
    fn active_hooks(&self) -> Vec<Arc<dyn ProxyHooks>>;
    /// Lets the owning module downcast back to its concrete host type.
    fn as_any_mut(&mut self) -> &mut dyn Any;
}

/// No extension host installed: every hook point passes the message through.
pub struct NoExtHooks;

impl ExtHookSource for NoExtHooks {
    fn active_hooks(&self) -> Vec<Arc<dyn ProxyHooks>> {
        Vec::new()
    }

    fn as_any_mut(&mut self) -> &mut dyn Any {
        self
    }
}
