extern crate serde_derive;

use std::cell::RefCell;
use std::collections::HashMap;
use std::fmt;
use std::path;

use hyper;
use hyper::rt::{Future, Stream};

use serde_derive::{Deserialize, Serialize};
use tokio;
use yup_oauth2;

// TODO: This should be implemented for the API so we can make it  generic
pub trait WrapiApi {
  fn call<'a, B, C>(&self, name: &str, request: B) -> Result<Box<C>, WrapiError>
  where
    B: WrapiRequest,
    C: WrapiResult + 'a;
}

// Since these traits are public, I want to only require primitives for ease of use.
pub trait WrapiRequest {
  fn build_uri(&self, base_url: &str) -> Result<String, WrapiError>;
  fn build_body(&self) -> Result<String, WrapiError>;
  fn build_headers(&self) -> Result<Vec<(String, String)>, WrapiError>;
}

pub trait WrapiResult: Send + Sync {
  // fn call<A, T: WrapiResult>(api: API<A>) -> Result<T, WrapiError>;
  fn parse(headers: Vec<(String, String)>, body: Vec<u8>) -> Result<Box<Self>, WrapiError>;
}

pub trait GetToken: yup_oauth2::GetToken {}

#[derive(Debug)]
pub enum WrapiError {
  Connection(String),
  Json(String),
  Http(String),
  General(String),
}

impl From<&str> for WrapiError {
  fn from(err: &str) -> WrapiError {
    WrapiError::General(format!("{:#?}", err))
  }
}
impl From<String> for WrapiError {
  fn from(err: String) -> WrapiError {
    WrapiError::General(format!("{:#?}", err))
  }
}
impl From<serde_json::Error> for WrapiError {
  fn from(err: serde_json::Error) -> WrapiError {
    WrapiError::Json(format!("{:#?}", err))
  }
}

impl From<hyper::Error> for WrapiError {
  fn from(err: hyper::Error) -> WrapiError {
    WrapiError::Http(format!("{:#?}", err))
  }
}

impl From<std::str::Utf8Error> for WrapiError {
  fn from(err: std::str::Utf8Error) -> WrapiError {
    WrapiError::General(format!("{:#?}", err))
  }
}

impl From<std::string::FromUtf8Error> for WrapiError {
  fn from(err: std::string::FromUtf8Error) -> WrapiError {
    WrapiError::General(format!("{:#?}", err))
  }
}

#[derive(Clone, Copy, Debug, Serialize, Deserialize)]
pub enum MimeType {
  Null,
  #[serde(rename = "application/json")]
  Json,
}

impl MimeType {
  pub fn to_string(&self) -> String {
    let mut value = serde_json::to_string(self).unwrap();
    value.pop();
    value.remove(0);
    value
  }
}

#[derive(Clone, Copy, Debug)]
pub enum AuthMethod {
  None,
  ServiceAccount,
}

#[derive(Clone, Copy, Debug)]
pub enum RequestMethod {
  GET,
  POST,
  DELETE,
  UPDATE,
}

/// A specific function to be called within an external api.
pub struct Endpoint {
  pub base_url: &'static str,
  pub auth_method: AuthMethod,
  pub request_method: RequestMethod,
  pub scopes: Vec<&'static str>,
  pub request_mime_type: MimeType,
  pub response_mime_type: MimeType,
}

impl Endpoint {
  pub fn build_request<T: WrapiRequest>(
    &self,
    request: T,
  ) -> Result<hyper::Request<hyper::Body>, WrapiError> {
    let mut req = hyper::Request::new(hyper::Body::empty());
    *req.uri_mut() = request.build_uri(self.base_url)?.parse().unwrap();
    *req.body_mut() = hyper::Body::from(request.build_body()?);

    for h in request.build_headers()?.into_iter() {
      let name: hyper::header::HeaderName = h.0.parse().unwrap();
      let value: hyper::header::HeaderValue = h.1.parse().unwrap();
      req.headers_mut().insert(name, value);
    }
    req.headers_mut().insert(
      hyper::header::CONTENT_TYPE,
      hyper::header::HeaderValue::from_str(&self.request_mime_type.to_string()[..]).unwrap(),
    );

    Ok(req)
  }

  pub fn get_scopes(&self) -> Vec<&'static str> {
    self.scopes.clone()
  }
}

impl fmt::Debug for Endpoint {
  fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
    write!(
      f,
      "\tEndpoint:\n\t\tBase Url: {:#?}\n\t\tAuth Method: {:#?}\n\t\tScopes: {:#?}\n\t\tRequest Mime Type: {:#?}\n\t\tResponse Mime Type: {:#?}",
      self.base_url, self.auth_method, self.scopes, self.request_mime_type, self.response_mime_type
    )
  }
}

// #[derive(Debug)]
pub struct API<A> {
  client: Box<hyper::Client<hyper_rustls::HttpsConnector<hyper::client::connect::HttpConnector>>>,
  service_account: Option<RefCell<A>>,
  endpoints: HashMap<String, Endpoint>,
  runtime: RefCell<tokio::runtime::Runtime>,
}

impl<A> fmt::Debug for API<A> {
  fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
    write!(
      f,
      "API:\n\tClient:\n\t\t{:#?}\n\tEndpoints\n\t\t{:#?}",
      self.client, self.endpoints
    )
  }
}

impl<A> API<A>
where
  A: yup_oauth2::GetToken,
{
  pub fn new(auth: Option<A>) -> API<A> {
    let https_conn = hyper_rustls::HttpsConnector::new(4);
    let client: hyper::client::Client<_, hyper::Body> = hyper::Client::builder().build(https_conn);
    API {
      client: Box::new(client),
      service_account: match auth {
        None => None,
        Some(value) => Some(RefCell::new(value)),
      },
      endpoints: HashMap::new(),
      runtime: RefCell::new(tokio::runtime::Runtime::new().unwrap()),
    }
  }

  pub fn add_endpoint(mut self, name: String, endpoint: Endpoint) -> API<A> {
    self.endpoints.insert(name, endpoint);
    self
  }

  pub fn get_endpoint(&self, name: String) -> Result<&Endpoint, WrapiError> {
    let endpoint = self.endpoints.get(&name);
    match endpoint {
      Some(point) => Ok(point),
      None => Err(WrapiError::General(format!(
        "'{}' is not a registered endpoint",
        name
      ))),
    }
  }

  pub fn add_token(
    &self,
    auth_method: AuthMethod,
    scopes: Vec<&str>,
    mut req: hyper::Request<hyper::Body>,
  ) -> Result<hyper::Request<hyper::Body>, WrapiError> {
    match auth_method {
      // The service account needs to be added at https://admin.google.com/AdminHome?chromeless=1#OGX:ManageOauthClients
      AuthMethod::None => Ok(req),
      AuthMethod::ServiceAccount => match &self.service_account {
        None => Ok(req),
        Some(sa) => {
          let fut = sa.borrow_mut().token(scopes);
          // .map_err(|e| println!("error: {:?}", e))
          // .and_then(|t| Ok(t));

          let token = self
            .runtime
            .borrow_mut()
            .block_on(fut)
            .expect("Blocked trying to run rt");

          req.headers_mut().insert(
            hyper::header::HeaderName::from_lowercase(b"authorization").unwrap(),
            hyper::header::HeaderValue::from_str(&format!("Bearer {}", token.access_token)[..])
              .unwrap(),
          );
          Ok(req)
        }
      },
    }
  }

  fn build_request(
    &self,
    endpoint_name: &str,
    request: impl WrapiRequest,
  ) -> Result<hyper::Request<hyper::Body>, WrapiError> {
    // Get the endpoint
    let endpoint = self.get_endpoint(endpoint_name.to_string())?;
    // Build the request
    let req = endpoint.build_request(request)?;
    Ok(req)
  }
}

impl<A> WrapiApi for API<A>
where
  A: yup_oauth2::GetToken,
{
  fn call<'a, B, C>(&self, name: &str, request: B) -> Result<Box<C>, WrapiError>
  where
    B: WrapiRequest,
    C: WrapiResult + 'a,
  {
    let endpoint = self.get_endpoint(name.to_string())?;

    let req = self.build_request(name, request)?;
    // Add a token, if needed
    let req = self.add_token(endpoint.auth_method, endpoint.get_scopes(), req)?;
    println!("{:#?}", req);

    // Run the request
    let runnable = self
      .client
      .request(req)
      .and_then(|res| {
        // println!("Call Result Headers:{:#?}", res.headers());
        res.into_body().concat2()
      })
      .from_err::<WrapiError>()
      .and_then(|body| Ok(body.iter().cloned().collect::<Vec<u8>>()))
      .map_err(|e| println!("error: {:?}", e));

    let result = self
      .runtime
      .borrow_mut()
      .block_on(runnable)
      .expect("Blocked trying to run rt for call");
    // println!("Body String:\n{:#?}", std::str::from_utf8(&result));
    C::parse(vec![], result)
  }
}

pub fn build_service_account(path: &str, as_user: Option<&str>) -> impl yup_oauth2::GetToken {
  let creds = yup_oauth2::service_account_key_from_file(path::Path::new(path)).unwrap();
  let sa = yup_oauth2::ServiceAccountAccess::new(creds);
  match as_user {
    Some(user) => sa.sub(user.to_string()).build(),
    None => sa.build(),
  }
}
