pub mod pm;

#[cfg(test)]
mod tests {
    use crate::pm::{Authorization, Id, Item, PasswordManagerError};
    use rand::{distributions::Alphanumeric, Rng}; // 0.8
    use super::*;

    fn generate_string(size: usize) -> String {
        rand::thread_rng()
            .sample_iter(&Alphanumeric)
            .take(size)
            .map(char::from)
            .collect()
    }

    fn generate_random_item(size: usize) -> (Id, Item){
        let id = generate_string(size);
        let user = id.clone();
        let pass = generate_string(size);
        let item = Item::new(user , pass);
        (id, item)
    }

    #[test]
    fn when_no_auth_return_error() {
        let mut manager = pm::PasswordManager::new();
        let (id, item) = generate_random_item(10);
        let result = manager.add(id, item, "passas".to_owned());
        assert_eq!(result, Err(PasswordManagerError{}));
    }

    #[test]
    fn when_incorrect_auth_return_error() {
        let mut manager = pm::PasswordManager::new();
        let password = generate_string(10);
        let incorrect_password = generate_string(10);
        let _ = manager.set_authorization("".to_owned(), Authorization::new(password));
        let (id, item) = generate_random_item(10);
        let result = manager.add(id, item, incorrect_password);
        assert_eq!(result, Err(PasswordManagerError{}));
    }

    #[test]
    fn when_correct_auth_add_item() {
        let mut manager = pm::PasswordManager::new();
        let password = generate_string(10);
        let _ = manager.set_authorization("".to_owned(), Authorization::new(password.clone()));
        let (id, item) = generate_random_item(10);
        let result = manager.add(id, item, password);
        assert_eq!(result, Ok(()));
    }

    #[test]
    fn when_correct_auth_add_and_get_item() {
        let mut manager = pm::PasswordManager::new();
        let password = generate_string(10);
        let _ = manager.set_authorization("".to_owned(), Authorization::new(password.clone()));
        let (id, item) = generate_random_item(10);
        let result = manager.add(id.clone(), item.clone(), password.clone());
        assert_eq!(result, Ok(()));
        let result = manager.get(&id, password);
        assert_eq!(result, Ok(&item));
    }

    #[test]
    fn when_correct_auth_get_err() {
        let mut manager = pm::PasswordManager::new();
        let password = generate_string(10);
        let _ = manager.set_authorization("".to_owned(), Authorization::new(password.clone()));
        let id = generate_string(10);
        let result = manager.get(&id, password);
        assert_eq!(result, Err(PasswordManagerError{}));
    }

    #[test]
    fn when_correct_auth_remove() {
        let mut manager = pm::PasswordManager::new();
        let password = generate_string(10);
        let _ = manager.set_authorization("".to_owned(), Authorization::new(password.clone()));
        let id = generate_string(10);
        let result = manager.remove(&id,password);
        assert_eq!(result, Ok(()));
    }

    #[test]
    fn when_incorrect_auth_remove_err() {
        let mut manager = pm::PasswordManager::new();
        let password = generate_string(10);
        let _ = manager.set_authorization("".to_owned(), Authorization::new(password.clone()));
        let id = generate_string(10);
        let result = manager.remove(&id,"".to_owned());
        assert_eq!(result, Err(PasswordManagerError{}));
    }

    #[test]
    fn when_correct_auth_remove_get_err() {
        let mut manager = pm::PasswordManager::new();
        let password = generate_string(10);
        let _ = manager.set_authorization("".to_owned(), Authorization::new(password.clone()));
        let (id, item) = generate_random_item(10);
        let result = manager.add(id.clone(), item.clone(), password.clone());
        assert_eq!(result, Ok(()));
        let result = manager.get(&id,password.clone());
        assert_eq!(result, Ok(&item));
        let result = manager.remove(&id,password.clone());
        assert_eq!(result, Ok(()));
        let result = manager.get(&id,password.clone());
        assert_eq!(result, Err(PasswordManagerError{}));
    }

    #[test]
    fn when_correct_auth_change_auth() {
        let mut manager = pm::PasswordManager::new();
        let password = generate_string(10);
        let _ = manager.set_authorization("".to_owned(), Authorization::new(password.clone()));
        let new_password = generate_string(10);
        let result = manager.set_authorization(password, Authorization::new(new_password.clone()));
        assert_eq!(result, Ok(()));
    }

}
