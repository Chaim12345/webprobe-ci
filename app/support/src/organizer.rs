//! Burp-style Organizer: a flat, named collection of saved requests and
//! responses that survives across tools. Items keep their id for their whole
//! lifetime; removing one never renumbers the others.

/// One saved request/response pair with user metadata.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct OrganizerItem {
    pub id: u64,
    pub name: String,
    pub note: String,
    pub request: String,
    pub response: String,
    pub created: u64,
    /// Owning collection id; 0 is the built-in Inbox.
    pub collection: u64,
}

/// A named user collection (Burp's Organizer "New collection").
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Collection {
    pub id: u64,
    pub name: String,
    /// Free-text description shown on the collection's About tab.
    pub description: String,
}

/// Ordered-by-id item store. Ids are monotonic and never reused.
#[derive(Debug, Default)]
pub struct Organizer {
    pub items: Vec<OrganizerItem>,
    pub next_id: u64,
    pub collections: Vec<Collection>,
    pub next_collection_id: u64,
    /// Items added to the Inbox since the UI last saw it; drives the rail's
    /// orange new-item dot.
    pub inbox_new: u64,
}

impl Organizer {
    pub fn new() -> Self {
        Self {
            items: Vec::new(),
            next_id: 1,
            collections: Vec::new(),
            next_collection_id: 1,
            inbox_new: 0,
        }
    }

    fn unique_name(&self, name: &str, except: u64) -> String {
        let base = match name.trim() {
            "" => "New collection".to_string(),
            n => n.to_string(),
        };
        let mut unique = base.clone();
        let mut n = 2;
        while unique.eq_ignore_ascii_case("Inbox")
            || self
                .collections
                .iter()
                .any(|c| c.id != except && c.name == unique)
        {
            unique = format!("{base} ({n})");
            n += 1;
        }
        unique
    }

    /// Create a named collection and return its id. A blank name becomes
    /// "New collection"; a duplicate name (or "Inbox") gets " (2)", " (3)", ...
    /// appended, as Burp does.
    pub fn add_collection(&mut self, name: &str) -> u64 {
        let id = self.next_collection_id;
        self.next_collection_id = self.next_collection_id.saturating_add(1);
        let name = self.unique_name(name, 0);
        self.collections.push(Collection {
            id,
            name,
            description: String::new(),
        });
        id
    }

    /// Copy a collection and its items under a deduplicated name; returns the
    /// new collection id, or None when `id` does not exist.
    pub fn duplicate_collection(&mut self, id: u64) -> Option<u64> {
        let (name, description) = {
            let c = self.collections.iter().find(|c| c.id == id)?;
            (c.name.clone(), c.description.clone())
        };
        let new_id = self.add_collection(&name);
        if let Some(c) = self.collections.iter_mut().find(|c| c.id == new_id) {
            c.description = description;
        }
        let items: Vec<OrganizerItem> = self
            .items
            .iter()
            .filter(|i| i.collection == id)
            .cloned()
            .collect();
        for i in items {
            let nid = self.next_id;
            self.next_id = self.next_id.saturating_add(1);
            self.items.push(OrganizerItem {
                id: nid,
                collection: new_id,
                ..i
            });
        }
        Some(new_id)
    }

    /// Copy an item into a collection (0 = Inbox) and return the copy's id.
    pub fn copy_item(&mut self, id: u64, collection: u64) -> Option<u64> {
        if collection != 0 && !self.collections.iter().any(|c| c.id == collection) {
            return None;
        }
        let item = self.items.iter().find(|i| i.id == id)?.clone();
        let nid = self.next_id;
        self.next_id = self.next_id.saturating_add(1);
        self.items.push(OrganizerItem {
            id: nid,
            collection,
            ..item
        });
        Some(nid)
    }

    /// Set a collection's About-tab description; false when it does not exist.
    pub fn set_collection_description(&mut self, id: u64, text: &str) -> bool {
        match self.collections.iter_mut().find(|c| c.id == id) {
            Some(c) => {
                c.description = text.to_string();
                true
            }
            None => false,
        }
    }

    /// Rename with the same uniqueness rules; blank names are rejected.
    pub fn rename_collection(&mut self, id: u64, name: &str) -> bool {
        if name.trim().is_empty() || !self.collections.iter().any(|c| c.id == id) {
            return false;
        }
        let name = self.unique_name(name, id);
        if let Some(c) = self.collections.iter_mut().find(|c| c.id == id) {
            c.name = name;
        }
        true
    }

    /// Delete a collection; its items move to the Inbox (collection 0),
    /// they are not deleted (policy D-CEO-02). False when the id does not
    /// exist.
    pub fn remove_collection(&mut self, id: u64) -> bool {
        let before = self.collections.len();
        self.collections.retain(|c| c.id != id);
        if self.collections.len() != before {
            for i in self.items.iter_mut() {
                if i.collection == id {
                    i.collection = 0;
                }
            }
            true
        } else {
            false
        }
    }

    /// Point every item whose collection no longer exists back at the Inbox.
    pub fn repair_collections(&mut self) {
        let ids: Vec<u64> = self.collections.iter().map(|c| c.id).collect();
        for i in self.items.iter_mut() {
            if i.collection != 0 && !ids.contains(&i.collection) {
                i.collection = 0;
            }
        }
    }

    pub fn collection_len(&self, id: u64) -> usize {
        self.items.iter().filter(|i| i.collection == id).count()
    }

    /// Store a new item in the Inbox and return its id. `now` is the
    /// creation timestamp supplied by the caller (epoch seconds or millis).
    /// Measured Burp Community 2026.11.2: Send to Organizer always lands in
    /// the Inbox, even with a custom collection selected; items move into
    /// collections only via move/copy.
    pub fn add(&mut self, name: &str, note: &str, request: &str, response: &str, now: u64) -> u64 {
        let id = self.next_id;
        self.next_id = self.next_id.saturating_add(1);
        self.inbox_new = self.inbox_new.saturating_add(1);
        self.items.push(OrganizerItem {
            id,
            name: name.to_string(),
            note: note.to_string(),
            request: request.to_string(),
            response: response.to_string(),
            created: now,
            collection: 0,
        });
        id
    }

    /// Note that the UI is showing the Inbox; clears the new-item dot.
    pub fn mark_inbox_seen(&mut self) {
        self.inbox_new = 0;
    }

    /// Remove the item with `id`; false when it does not exist.
    pub fn remove(&mut self, id: u64) -> bool {
        let before = self.items.len();
        self.items.retain(|i| i.id != id);
        self.items.len() != before
    }

    pub fn rename(&mut self, id: u64, name: &str) -> bool {
        match self.items.iter_mut().find(|i| i.id == id) {
            Some(item) => {
                item.name = name.to_string();
                true
            }
            None => false,
        }
    }

    pub fn set_note(&mut self, id: u64, note: &str) -> bool {
        match self.items.iter_mut().find(|i| i.id == id) {
            Some(item) => {
                item.note = note.to_string();
                true
            }
            None => false,
        }
    }

    pub fn get(&self, id: u64) -> Option<&OrganizerItem> {
        self.items.iter().find(|i| i.id == id)
    }

    /// All items sorted by id (insertion order, since ids only grow).
    pub fn list(&self) -> Vec<&OrganizerItem> {
        let mut out: Vec<&OrganizerItem> = self.items.iter().collect();
        out.sort_by_key(|i| i.id);
        out
    }

    /// Case-insensitive substring match over name and note.
    pub fn search(&self, text: &str) -> Vec<&OrganizerItem> {
        let needle = text.trim().to_lowercase();
        let mut out: Vec<&OrganizerItem> = if needle.is_empty() {
            self.items.iter().collect()
        } else {
            self.items
                .iter()
                .filter(|i| {
                    i.name.to_lowercase().contains(&needle)
                        || i.note.to_lowercase().contains(&needle)
                })
                .collect()
        };
        out.sort_by_key(|i| i.id);
        out
    }

    /// Move an item into a collection (0 = Inbox).
    pub fn move_item(&mut self, id: u64, collection: u64) -> bool {
        if collection != 0 && !self.collections.iter().any(|c| c.id == collection) {
            return false;
        }
        match self.items.iter_mut().find(|i| i.id == id) {
            Some(i) => {
                i.collection = collection;
                true
            }
            None => false,
        }
    }

    pub fn len(&self) -> usize {
        self.items.len()
    }

    pub fn is_empty(&self) -> bool {
        self.items.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn org() -> Organizer {
        let mut o = Organizer::new();
        o.add("Login", "auth flow", "GET /login HTTP/1.1", "200 OK", 10);
        o.add(
            "Upload",
            "file upload",
            "POST /up HTTP/1.1",
            "201 Created",
            20,
        );
        o.add(
            "Admin",
            "admin panel",
            "GET /admin HTTP/1.1",
            "403 Forbidden",
            30,
        );
        o
    }

    #[test]
    fn add_and_get() {
        let o = org();
        assert_eq!(o.len(), 3);
        let item = o.get(2).expect("item 2");
        assert_eq!(item.name, "Upload");
        assert_eq!(item.note, "file upload");
        assert_eq!(item.request, "POST /up HTTP/1.1");
        assert_eq!(item.response, "201 Created");
        assert_eq!(item.created, 20);
        assert!(o.get(99).is_none());
    }

    #[test]
    fn new_collection_is_named_and_not_an_inbox_item() {
        let mut o = org();
        let items_before = o.len();
        let a = o.add_collection("");
        let b = o.add_collection("Auth bugs");
        let c = o.add_collection("Auth bugs");
        assert_eq!(o.len(), items_before, "+ New must not add an item");
        assert!(o.items.iter().all(|i| i.name != "New item"));
        assert_eq!(o.collections.len(), 3);
        assert_eq!(o.collections[0].name, "New collection");
        assert_eq!(o.collections[1].name, "Auth bugs");
        assert_eq!(o.collections[2].name, "Auth bugs (2)", "Burp dedupe suffix");
        assert!(a != b && b != c);
        assert!(o.rename_collection(b, "Renamed"));
        assert!(!o.rename_collection(b, "  "));
        assert!(!o.rename_collection(99, "x"));
        assert_eq!(o.collection_len(0), items_before);
        assert!(o.move_item(1, b));
        assert!(!o.move_item(1, 99));
        assert_eq!(o.collection_len(b), 1);
        assert_eq!(o.collection_len(0), items_before - 1);
        assert!(o.rename_collection(b, "New collection"));
        assert_eq!(
            o.collections[1].name, "New collection (2)",
            "rename dedupes"
        );
        assert!(o.rename_collection(b, "inbox"));
        assert_eq!(o.collections[1].name, "inbox (2)");
        let filed = o.add("sent", "", "GET /", "", 50);
        assert_eq!(
            o.get(filed).unwrap().collection,
            0,
            "sends always land in the Inbox (measured Burp 2026.11.2)"
        );
        o.move_item(filed, b);
        assert_eq!(o.get(filed).unwrap().collection, b);
        o.move_item(3, c);
        let before_1 = o.get(1).unwrap().clone();
        let before_filed = o.get(filed).unwrap().clone();
        assert!(o.remove_collection(b));
        for (id, before) in [(1, before_1), (filed, before_filed)] {
            let after = o.get(id).expect("items survive the delete");
            assert_eq!(after.id, before.id, "id preserved");
            assert_eq!(after.name, before.name, "name preserved");
            assert_eq!(after.note, before.note, "note preserved");
            assert_eq!(after.request, before.request, "request evidence preserved");
            assert_eq!(
                after.response, before.response,
                "response evidence preserved"
            );
            assert_eq!(after.created, before.created, "timestamp preserved");
            assert_eq!(after.collection, 0, "moved to the Inbox (D-CEO-02)");
        }
        assert_eq!(
            o.get(3).unwrap().collection,
            c,
            "unrelated collections untouched"
        );
        assert!(!o.remove_collection(b), "repeated deletion is a no-op");
        assert_eq!(o.get(1).unwrap().collection, 0, "still in the Inbox");
        o.items[0].collection = 77;
        o.repair_collections();
        assert_eq!(o.items[0].collection, 0, "orphans remapped");
        assert_eq!(o.add_collection("Inbox"), 4);
        assert_eq!(o.collections.last().unwrap().name, "Inbox (2)");
    }

    #[test]
    fn duplicate_collection_copies_items_under_a_deduped_name() {
        let mut o = org();
        let b = o.add_collection("Auth bugs");
        o.move_item(1, b);
        o.move_item(2, b);
        let copy = o.duplicate_collection(b).expect("duplicate");
        assert!(copy != b);
        let name = o
            .collections
            .iter()
            .find(|c| c.id == copy)
            .unwrap()
            .name
            .clone();
        assert_eq!(name, "Auth bugs (2)");
        assert_eq!(o.collection_len(copy), 2, "items copied");
        assert_eq!(o.collection_len(b), 2, "originals kept");
        let new_ids: Vec<u64> = o
            .items
            .iter()
            .filter(|i| i.collection == copy)
            .map(|i| i.id)
            .collect();
        assert!(new_ids.iter().all(|id| *id > 3), "copies get fresh ids");
        assert!(o.duplicate_collection(99).is_none());
    }

    #[test]
    fn copy_item_clones_into_the_target_collection() {
        let mut o = org();
        let b = o.add_collection("Auth bugs");
        let nid = o.copy_item(1, b).expect("copy");
        assert!(nid > 3, "fresh id");
        let item = o.get(nid).unwrap();
        assert_eq!(item.name, "Login");
        assert_eq!(item.note, "auth flow");
        assert_eq!(item.collection, b);
        assert_eq!(o.get(1).unwrap().collection, 0, "original stays in Inbox");
        assert!(o.copy_item(1, 99).is_none());
        assert!(o.copy_item(99, b).is_none());
        assert!(o.set_collection_description(b, "about this"));
        assert!(!o.set_collection_description(99, "nope"));
        assert_eq!(
            o.collections
                .iter()
                .find(|c| c.id == b)
                .unwrap()
                .description,
            "about this"
        );
    }

    #[test]
    fn sends_always_land_in_the_inbox() {
        // Measured Burp Community 2026.11.2: Send to Organizer (Ctrl+O) always
        // lands in the Inbox, even with a custom collection selected.
        let mut o = Organizer::new();
        o.add_collection("Auth");
        let sent = o.add("sent", "", "GET /", "", 1);
        assert_eq!(o.get(sent).unwrap().collection, 0);
        assert_eq!(o.inbox_new, 1, "new-item dot count grows");
        o.mark_inbox_seen();
        assert_eq!(o.inbox_new, 0);
        o.add("again", "", "GET /", "", 2);
        assert_eq!(o.inbox_new, 1);
    }

    #[test]
    fn remove_reports_success() {
        let mut o = org();
        assert!(o.remove(2));
        assert!(!o.remove(2));
        assert_eq!(o.len(), 2);
        assert!(o.get(2).is_none());
    }

    #[test]
    fn rename_and_set_note() {
        let mut o = org();
        assert!(o.rename(1, "Login v2"));
        assert!(o.set_note(1, "updated note"));
        assert!(!o.rename(42, "nope"));
        assert!(!o.set_note(42, "nope"));
        let item = o.get(1).unwrap();
        assert_eq!(item.name, "Login v2");
        assert_eq!(item.note, "updated note");
        // Other items untouched.
        assert_eq!(o.get(2).unwrap().name, "Upload");
    }

    #[test]
    fn search_matches_name_and_note_case_insensitively() {
        let o = org();
        assert_eq!(o.search("login").len(), 1);
        assert_eq!(o.search("LOGIN")[0].id, 1);
        assert_eq!(o.search("file").len(), 1); // note only
        assert_eq!(o.search("panel").len(), 1); // note only
        assert!(o.search("missing").is_empty());
        assert_eq!(o.search("  ").len(), 3); // empty query lists all
    }

    #[test]
    fn ids_stay_stable_after_removal() {
        let mut o = org();
        o.remove(2);
        assert_eq!(o.add("New", "", "GET /new", "", 40), 4);
        let ids: Vec<u64> = o.list().iter().map(|i| i.id).collect();
        assert_eq!(ids, vec![1, 3, 4]);
        assert_eq!(o.get(3).unwrap().name, "Admin");
    }

    #[test]
    fn list_is_sorted_by_id() {
        let mut o = Organizer::new();
        // Insertion order is already id order; list must be stable regardless.
        let a = o.add("a", "", "", "", 1);
        let b = o.add("b", "", "", "", 2);
        let ids: Vec<u64> = o.list().iter().map(|i| i.id).collect();
        assert_eq!(ids, vec![a, b]);
    }
}
