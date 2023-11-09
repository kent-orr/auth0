
#' Retrieve an Auth0 API Token
#'
#' This function retrieves an Auth0 API token by either using an existing token or by making
#' an API call to obtain a new token. It uses client credentials grant.
#'
#'  @inheritParams auth0_config
#'
#' @return A character string representing the Auth0 API token.
#'
#' @examples
#' \dontrun{
#'   client <- "your_client_id"
#'   secret <- "your_client_secret"
#'   auth0_api_token(client, secret)
#' }
#'
#' @export
auth0_api_token <- function(config_file) {
  if (Sys.getenv("AUTH0_TOKEN") != "" && as.POSIXct(as.numeric(Sys.getenv("AUTH0_TOKEN_EXP"))) > Sys.time()) {
    print("using existing token")
    return(Sys.getenv("AUTH0_TOKEN"))
  }

  print("requesting new token")
  config = auth0_config(config_file)
  response = httr::POST(paste0(config$auth0_config$api_url, "/oauth/token")
                        , encode = "form"
                        , body  = list(
                          grant_type = "client_credentials"
                          , client_id = config$auth0_config$credentials$key
                          , client_secret = config$auth0_config$credentials$secret
                          , audience = paste0(config$auth0_config$api_url, "/api/v2/"))
  )

  response_parsed = response$content |> rawToChar() |> jsonlite::fromJSON()
  Sys.setenv("AUTH0_TOKEN" = response_parsed$access_token)
  Sys.setenv("AUTH0_TOKEN_EXP" = Sys.time() + response_parsed$expires_in)
  return(response_parsed$access_token)
}

#' Manage Auth0 Users
#'
#' This function provides an interface for managing users in Auth0. It supports
#' actions for getting and updating user details.
#'
#' @param user_id Character string, the ID of the user you want to manage.
#' @param action Character string, the action to be performed; either 'get', 'update', 'create', or 'delete'
#'               Default is 'get'.
#' @param body List, additional body parameters for the 'update' action.
#'
#' @return A list representing the parsed response from the Auth0 API.
#'
#' @examples
#' \dontrun{
#'   auth0_user_management(user_id, action)
#'
#'   body <- list(user_metadata = list(theme='dark'))
#'   auth0_user_management(user_id, "update, body)
#' }
#'
#' @importFrom httr GET PATCH add_headers
#' @importFrom jsonlite fromJSON
#' @export
auth0_user_management <- function(user_id, action = "get", body = list(), config_file = NULL) {
  config = if (is.null(config_file)) do.call(auth0_config, list()) else auth0_config(config_file)
  token = if (is.null(config_file)) do.call(auth0_api_token, list()) else auth0_api_token(config_file)
  if (action == "get") {
    response = GET(paste0(config$auth0_config$api_url, '/api/v2/users/', user_id)
                   , add_headers(authorization = paste("Bearer", token))
                   , encode = "json"
    )
    if (response$status_code != 200) {cat("Error", response$status_code, "\n")}
    response_parsed = response$content |> rawToChar() |> jsonlite::fromJSON()
  }
  if (action == "update") {
    response = PATCH(paste0(config$auth0_config$api_url, '/api/v2/users/', user_id)
                     , add_headers(authorization = paste("Bearer", token))
                     , body = body
                     , encode = "json")
    if (response$status_code != 200) {cat("Error", response$status_code, "\n")}
    response_parsed = response$content |> rawToChar() |> jsonlite::fromJSON()
  }

  if (action == "create") {
    response = POST(paste0(config$auth0_config$api_url, '/api/v2/users/')
                    , add_headers(authorization = paste("Bearer", token))
                    , body = body
                    , encode = "json"
                    )
    if (response$status_code != 201) {cat("Error", response$status_code, "\n")}
  }

  if (action == "delete") {
    response = DELETE(paste0(config$auth0_config$api_url, '/api/v2/users/', user_id)
                      , add_headers(authorization = paste("Bearer", token))
                      , encode = "json"
    )
    if (response$status_code != 204) {cat("Error", response$status_code, "\n")}

  }

  response_parsed = response$content |> rawToChar() |> jsonlite::fromJSON()
  response$content |> rawToChar()

  return(response_parsed)
}
