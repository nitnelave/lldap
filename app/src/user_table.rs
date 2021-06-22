use crate::api::HostService;
use anyhow::{anyhow, Result};
use lldap_model::*;
use yew::format::Json;
use yew::prelude::*;
use yew::services::{fetch::FetchTask, ConsoleService};

pub struct UserTable {
    link: ComponentLink<Self>,
    users: Option<Result<Vec<User>>>,
    // Used to keep the request alive long enough.
    _task: Option<FetchTask>,
}

pub enum Msg {
    ListUsersResponse(Result<Vec<User>>),
}

impl UserTable {
    fn get_users(&mut self, req: ListUsersRequest) {
        match HostService::list_users(req, self.link.callback(Msg::ListUsersResponse)) {
            Ok(task) => self._task = Some(task),
            Err(e) => {
                self._task = None;
                ConsoleService::log(format!("Error trying to fetch users: {}", e).as_str())
            }
        };
    }
}

impl Component for UserTable {
    type Message = Msg;
    type Properties = ();

    fn create(_: Self::Properties, link: ComponentLink<Self>) -> Self {
        let mut table = UserTable {
            link,
            _task: None,
            users: None,
        };
        table.get_users(ListUsersRequest { filters: None });
        table
    }

    fn update(&mut self, msg: Self::Message) -> ShouldRender {
        match msg {
            Msg::ListUsersResponse(Ok(users)) => {
                self.users = Some(Ok(users));
                ConsoleService::log(format!("Response: {:?}", Json(&self.users)).as_str());
                true
            }
            Msg::ListUsersResponse(Err(e)) => {
                self.users = Some(Err(anyhow!("Error listing users: {}", e)));
                true
            }
        }
    }

    fn change(&mut self, _: Self::Properties) -> ShouldRender {
        false
    }

    fn view(&self) -> Html {
        match &self.users {
            None => html! {{"Loading..."}},
            Some(Err(e)) => html! {<div>{"Error: "}{e.to_string()}</div>},
            Some(Ok(users)) => {
                let table_content: Vec<_> = users
                    .iter()
                    .map(|u| {
                        html! {
                            <tr>
                                <td>{&u.user_id}</td>
                                <td>{&u.email}</td>
                                <td>{&u.display_name.as_ref().unwrap_or(&String::new())}</td>
                                <td>{&u.first_name.as_ref().unwrap_or(&String::new())}</td>
                                <td>{&u.last_name.as_ref().unwrap_or(&String::new())}</td>
                                <td>{&u.ssh_pub_key.as_ref().unwrap_or(&String::new())}</td>
                                <td>{&u.wireguard_pub_key.as_ref().unwrap_or(&String::new())}</td>
                                <td>{&u.creation_date}</td>
                            </tr>
                        }
                    })
                    .collect();
                html! {
                    <table>
                      <tr>
                        <th>{"User ID"}</th>
                        <th>{"Email"}</th>
                        <th>{"Display name"}</th>
                        <th>{"First name"}</th>
                        <th>{"Last name"}</th>
                        <th>{"SSH Public Key"}</th>
                        <th>{"Wireguard Public Key"}</th>
                        <th>{"Creation date"}</th>
                      </tr>
                      {table_content}
                    </table>
                }
            }
        }
    }
}
