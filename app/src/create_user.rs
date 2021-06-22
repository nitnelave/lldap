use crate::api::HostService;
use anyhow::Result;
use lldap_model::*;
use yew::prelude::*;
use yew::services::{fetch::FetchTask, ConsoleService};
use yew_router::{
    agent::{RouteAgentDispatcher, RouteRequest},
    route::Route,
};

pub struct CreateUserForm {
    link: ComponentLink<Self>,
    route_dispatcher: RouteAgentDispatcher,
    node_ref: NodeRef,
    error: Option<anyhow::Error>,
    // Used to keep the request alive long enough.
    _task: Option<FetchTask>,
}

pub enum Msg {
    CreateUserResponse(Result<()>),
    SubmitForm,
}

impl CreateUserForm {
    fn create_user(&mut self, req: CreateUserRequest) {
        match HostService::create_user(req, self.link.callback(Msg::CreateUserResponse)) {
            Ok(task) => self._task = Some(task),
            Err(e) => {
                self._task = None;
                ConsoleService::log(format!("Error trying to create user: {}", e).as_str())
            }
        };
    }
}

impl Component for CreateUserForm {
    type Message = Msg;
    type Properties = ();

    fn create(_: Self::Properties, link: ComponentLink<Self>) -> Self {
        Self {
            link,
            route_dispatcher: RouteAgentDispatcher::new(),
            node_ref: NodeRef::default(),
            error: None,
            _task: None,
        }
    }

    fn update(&mut self, msg: Self::Message) -> ShouldRender {
        match msg {
            Msg::SubmitForm => {
                use wasm_bindgen::JsCast;
                let document = web_sys::window().unwrap().document().unwrap();
                let get_element = |name: &str| {
                    document
                        .get_element_by_id(name)
                        .unwrap()
                        .dyn_into::<web_sys::HtmlInputElement>()
                        .unwrap()
                        .value()
                };
                let req = CreateUserRequest {
                    user_id: get_element("username"),
                    email: get_element("email"),
                    display_name: Some(get_element("displayname")),
                    first_name: Some(get_element("firstname")),
                    last_name: Some(get_element("lastname")),
                    ssh_pub_key: Some(get_element("ssh_pub_key")),
                    wireguard_pub_key: Some(get_element("wireguard_pub_key")),
                    password: get_element("password"),
                };
                self.create_user(req);
            }
            Msg::CreateUserResponse(Ok(())) => {
                self.route_dispatcher
                    .send(RouteRequest::ChangeRoute(Route::new_no_state(
                        "/list_users",
                    )));
            }
            Msg::CreateUserResponse(Err(e)) => {
                ConsoleService::warn(&format!("Error listing users: {}", e));
            }
        }
        true
    }

    fn change(&mut self, _: Self::Properties) -> ShouldRender {
        false
    }

    fn view(&self) -> Html {
        html! {
            <form ref=self.node_ref.clone() onsubmit=self.link.callback(|e: FocusEvent| { e.prevent_default(); Msg::SubmitForm })>
                <div>
                    <label for="username">{"User name:"}</label>
                    <input type="text" id="username" />
                </div>
                <div>
                    <label for="email">{"Email:"}</label>
                    <input type="text" id="email" />
                </div>
                <div>
                    <label for="displayname">{"Display name:"}</label>
                    <input type="text" id="displayname" />
                </div>
                <div>
                    <label for="firstname">{"First name:"}</label>
                    <input type="text" id="firstname" />
                </div>
                <div>
                    <label for="lastname">{"Last name:"}</label>
                    <input type="text" id="lastname" />
                </div>
                <div>
                    <label for="ssh_pub_key">{"SSH Public Key:"}</label>
                    <input type="text" id="ssh_pub_key" />
                </div>
                <div>
                    <label for="wireguard_pub_key">{"Wireguard Public Key:"}</label>
                    <input type="text" id="wireguard_pub_key" />
                </div>
                <div>
                    <label for="password">{"Password:"}</label>
                    <input type="password" id="password" />
                </div>
                <button type="submit">{"Login"}</button>
                <div>
                { if let Some(e) = &self.error {
                    html! { e.to_string() }
                  } else { html! {} }
                }
                </div>
            </form>
        }
    }
}
