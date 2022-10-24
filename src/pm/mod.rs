use std::collections::HashMap;

pub type Id = String; // username for now

pub struct Authorization {
    password : String
}

impl Authorization {
    pub fn new(password : String) -> Self{ Self { password } }
    pub fn authorize(&self, password : String) -> bool {
        self.password == password
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct Item{
    username : String,
    password : String,
}

impl Item {
    pub fn new(username: String, password: String) -> Self {
        Self { username, password }
    }
}


#[derive(Debug, Clone, PartialEq)]
pub struct PasswordManagerError{
}


pub struct PasswordManager{
    inventory : HashMap<Id, Item>,
    auth : Option<Authorization>,
}

impl PasswordManager{
    pub fn new() -> Self{
        PasswordManager{
            inventory: HashMap::new(),
            auth: None
        }
    }

    fn authorize(&self, password: String) -> Result<(), PasswordManagerError> {
        match &self.auth {
            None => {Err(PasswordManagerError{})}
            Some(auth) => {
                if auth.authorize(password){
                    Ok(())
                }else{
                    Err(PasswordManagerError{})
                }
            }
        }
    }

    pub fn set_authorization(&mut self, password: String, auth : Authorization)
                             -> Result<(), PasswordManagerError>
    {
        match &self.auth {
            Some(_) => {self.authorize(password)?}
            _ => {}
        }
        self.auth = Some(auth);
        Ok(())

    }

    pub fn add(&mut self, id : Id, item : Item, password : String) -> Result<(), PasswordManagerError>{
        self.authorize(password)?;
        self.inventory.insert(id, item);
        Ok(())
    }

    pub fn remove(&mut self, id : &Id, password : String) -> Result<(), PasswordManagerError>{
        self.authorize(password)?;
        self.inventory.remove(id);
        Ok(())
    }

    pub fn get(&self, id : &Id, password: String) -> Result<&Item, PasswordManagerError>{
        self.authorize(password)?;
        self.inventory.get(id).map_or(Err(PasswordManagerError{}), Ok)
    }
}
