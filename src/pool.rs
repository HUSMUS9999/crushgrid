use std::sync::{Arc, Condvar, Mutex};

/// Hard memory-budget semaphore so in-flight buffers never exceed user's --mem limit.
/// Always allows at least one single chunk even if chunk_size > limit to guarantee forward progress.
#[derive(Clone)]
pub struct ByteBudget {
    inner: Arc<(Mutex<usize>, Condvar, usize)>,
}

impl ByteBudget {
    pub fn new(max_bytes: usize) -> Self {
        Self {
            inner: Arc::new((Mutex::new(0), Condvar::new(), max_bytes.max(1))),
        }
    }

    pub fn acquire(&self, bytes: usize) -> BudgetGuard {
        let (lock, cvar, max_bytes) = &*self.inner;
        let mut used = lock.lock().unwrap();
        // Wait until used + bytes <= max_bytes, or used == 0 (always let 1 chunk proceed)
        while *used > 0 && (*used).saturating_add(bytes) > *max_bytes {
            used = cvar.wait(used).unwrap();
        }
        *used = used.saturating_add(bytes);
        BudgetGuard {
            budget: self.clone(),
            bytes,
        }
    }

    #[allow(dead_code)]
    pub fn used_bytes(&self) -> usize {
        *self.inner.0.lock().unwrap()
    }

    #[allow(dead_code)]
    pub fn max_bytes(&self) -> usize {
        self.inner.2
    }
}

pub struct BudgetGuard {
    budget: ByteBudget,
    bytes: usize,
}

impl Drop for BudgetGuard {
    fn drop(&mut self) {
        let (lock, cvar, _) = &*self.budget.inner;
        let mut used = lock.lock().unwrap();
        *used = used.saturating_sub(self.bytes);
        cvar.notify_all();
    }
}
