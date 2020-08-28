/*
 * Copyright (c) 2020 Danonek <damian@danonek.dev>
 * All rights reserved.
 *
 * Authentication plugin for Mosquitto MQTT broker (https://mosquitto.org/)
 * Uses POST and JSON to validate replies from HTTP server.
 *
 */

#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <errno.h>

#include <curl/curl.h>
#include <json-c/json.h>

#include <mosquitto.h>
#include <mosquitto_plugin.h>
#include <mosquitto_broker.h>

/*
|--------------------------------------------------------------------------
| HTTP Endpoints and root account
|--------------------------------------------------------------------------
| Edit these to your own endpoints.
| And change the root account to your own root login.
*/

#define DEFAULT_USER_URI "https://localhost/login"
#define DEFAULT_ACL_URI "https://localhost/acl"
#define ROOT_ACCOUNT "Danonek"

static char *http_user_uri = NULL;
static char *http_acl_uri = NULL;

struct url_data
{
	size_t size;
	char* data;
};

size_t write_data(void *ptr, size_t size, size_t nmemb, struct url_data *data) 
{
	size_t index = data->size;
	size_t n = (size * nmemb);
	char* tmp;

	data->size += (size * nmemb);
	
#ifdef DEBUG_INFO
    fprintf(stderr, "pointer %p size=%ld nmemb=%ld\n", ptr, size, nmemb);
#endif

	tmp = realloc(data->data, data->size + 1);

	if (tmp) 
	{
		data->data = tmp;
	} 
	else 
	{
		if (data->data) 
		{
			free(data->data);
		}
		fprintf(stderr, "Failed to allocate memory.\n");
		return MOSQ_ERR_ACL_DENIED;
	}

	memcpy((data->data + index), ptr, n);
	data->data[data->size] = '\0';

	return size * nmemb;
}

int mosquitto_auth_plugin_version(void) 
{
	return MOSQ_AUTH_PLUGIN_VERSION;
}

int mosquitto_auth_plugin_init(void **user_data, struct mosquitto_opt *opts, int opt_count)
{
	int i = 0;
	for (i = 0; i < opt_count; i++)
	{
#ifdef DEBUG_INFO
		mosquitto_log_printf(MOSQ_LOG_DEBUG, "AuthOptions: key=%s, val=%s\n", opts[i].key, opts[i].value);
#endif
		
		if (strncmp(opts[i].key, "http_user_uri", 13) == 0) 
		{
			http_user_uri = opts[i].value;
		}
		
		if (strncmp(opts[i].key, "http_acl_uri", 12) == 0) 
		{
			http_acl_uri = opts[i].value;
		}
	}
	
	if (http_user_uri == NULL)
	{
		http_user_uri = DEFAULT_USER_URI;
	}
	
	if (http_acl_uri == NULL)
	{
		http_acl_uri = DEFAULT_ACL_URI;
	}
	
#ifdef DEBUG_INFO
	mosquitto_log_printf(MOSQ_LOG_INFO, "http_user_uri = %s, http_acl_uri = %s", http_user_uri, http_acl_uri);
#endif

	return MOSQ_ERR_SUCCESS;
}

int mosquitto_auth_plugin_cleanup(void *user_data, struct mosquitto_opt *opts, int opt_count)
{
	return MOSQ_ERR_SUCCESS;
}

int mosquitto_auth_security_init(void *user_data, struct mosquitto_opt *opts, int opt_count, bool reload)
{
	return MOSQ_ERR_SUCCESS;
}

int mosquitto_auth_security_cleanup(void *user_data, struct mosquitto_opt *opts, int opt_count, bool reload)
{
	return MOSQ_ERR_SUCCESS;
}

struct mosquitto_credentials 
{
	char username[32];
	char clientid[32];
};

struct mosquitto_credentials creds;

int mosquitto_auth_unpwd_check(void *user_data, struct mosquitto *client, const char *username, const char *password)
{
	if (username == NULL || password == NULL)
	{
		return MOSQ_ERR_AUTH;
	}
	
	mosquitto_log_printf(MOSQ_LOG_INFO, "mosquitto_auth_unpwd_check: username=%s, password=%s", username, password);
	
	CURL *curl;
	
	if ((curl = curl_easy_init()) == NULL)
	{
		mosquitto_log_printf(MOSQ_LOG_WARNING, "failed to initialize curl (curl_easy_init AUTH): %s", strerror(errno));
		
#ifdef DEBUG_INFO
		fprintf(stderr, "malloc(): %s [%s, %d]\n", strerror(errno), __FILE__, __LINE__);
#endif
		return MOSQ_ERR_AUTH;
	}
	
	char *escaped_login;
	char *escaped_password;
	
	escaped_login = curl_easy_escape(curl, username, 0);
	escaped_password = curl_easy_escape(curl, password, 0);
	size_t params_len = strlen("email=&password=") + strlen(escaped_login) + strlen(escaped_password) + 1;
	char* params = NULL;
	if ((params = malloc(params_len)) == NULL) 
	{ 
		mosquitto_log_printf(MOSQ_LOG_WARNING, "failed allocate data memory (%u): %s", params_len, strerror(errno));
		
#ifdef DEBUG_INFO
		fprintf(stderr, "malloc(): %s [%s, %d]\n", strerror(errno), __FILE__, __LINE__);
#endif
		return MOSQ_ERR_ACL_DENIED;
	}
	else
	{
		memset(params, 0, params_len);
		snprintf(params, params_len, "email=%s&password=%s", escaped_login, escaped_password);
	}

	struct url_data data;
	data.size = 0;
	data.data = malloc(1024);
	if (NULL == data.data) 
	{
		fprintf(stderr, "Failed to allocate memory.\n");
		return MOSQ_ERR_ACL_DENIED;
	}

	data.data[0] = '\0';

	CURLcode res;
	
	curl_easy_setopt(curl, CURLOPT_URL, DEFAULT_USER_URI);
	curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_data);
	curl_easy_setopt(curl, CURLOPT_FOLLOWLOCATION, 1L);
	curl_easy_setopt(curl, CURLOPT_POSTFIELDS, params);
	curl_easy_setopt(curl, CURLOPT_POSTFIELDSIZE, strlen(params));
	curl_easy_setopt(curl, CURLOPT_WRITEDATA, &data);
	
	res = curl_easy_perform(curl);
	
	if (res != CURLE_OK) 
	{
		fprintf(stderr, "curl_easy_perform() failed: %s\n",  curl_easy_strerror(res));
	}

	curl_easy_cleanup(curl);
	curl_free(escaped_login);
	curl_free(escaped_password);
	free(params);
	params = NULL;
	
#ifdef DEBUG_INFO
	printf("data.size: %ld bytes\n", data.size);
#endif

	struct json_object *jobj;
	jobj = json_tokener_parse(data.data);
	
#ifdef DEBUG_INFO
	printf("json object from data.data:\n%s\n", json_object_to_json_string_ext(jobj, JSON_C_TO_STRING_SPACED | JSON_C_TO_STRING_PRETTY));
#endif
	
	/*
	 * Parse JSON object below.
	 */
	struct json_object *errorObj, *userInfoObj, *code, *message, *clientid, *statusMessage;
	json_object_object_get_ex(jobj, "error", &errorObj);
	json_object_object_get_ex(errorObj, "code", &code);
	json_object_object_get_ex(errorObj, "message", &message);
	json_object_object_get_ex(errorObj, "user_info", &userInfoObj);
	json_object_object_get_ex(userInfoObj, "clientId", &clientid);
	json_object_object_get_ex(jobj, "status", &statusMessage);
	
	// Validate the reply.
	if (strcmp(json_object_get_string(statusMessage), "SUCCESS") == 0)
	{
		strcpy(creds.username, username);
		strcpy(creds.clientid, json_object_get_string(clientid));
		json_object_put(jobj);
		free(data.data);
		return MOSQ_ERR_SUCCESS;
	}
	
	json_object_put(jobj);
	free(data.data);
	return MOSQ_ERR_ACL_DENIED;
}

int mosquitto_auth_acl_check(void *user_data, int access, struct mosquitto *client, const struct mosquitto_acl_msg *msg)
{
	const char *username = creds.username;
	const char *clientid = creds.clientid;
	const char *topic = msg->topic;
	
	if (strcmp(username, ROOT_ACCOUNT) == 0)
	{
		return MOSQ_ERR_SUCCESS;
	}

	char access_name[10];
	
	if (access == MOSQ_ACL_READ)
	{
		sprintf(access_name, "read");
	} 
	else if (access == MOSQ_ACL_SUBSCRIBE)
	{
		sprintf(access_name, "subscribe");
	}
	else if (access == MOSQ_ACL_WRITE)
	{
		sprintf(access_name, "write");
	}
	else
	{
		sprintf(access_name, "none");
	}

#ifdef DEBUG_INFO
	fprintf(stderr, "mosquitto_auth_acl_check: clientid=%s, username=%s, topic=%s, access=%s\n", clientid, username, topic, access_name);
#endif

	mosquitto_log_printf(MOSQ_LOG_DEBUG, "mosquitto_auth_acl_check: clientid=%s, username=%s, topic=%s, access=%s", clientid, username, topic, access_name);

	CURL *curl;
	
	if ((curl = curl_easy_init()) == NULL)
	{
		mosquitto_log_printf(MOSQ_LOG_WARNING, "failed to initialize curl (curl_easy_init AUTH): %s", strerror(errno));
		
#ifdef DEBUG_INFO
		fprintf(stderr, "malloc(): %s [%s, %d]\n", strerror(errno), __FILE__, __LINE__);
#endif
		return MOSQ_ERR_AUTH;
	}

	char *escaped_clientid;
	char *escaped_login;
	char *escaped_topic;
	escaped_clientid = curl_easy_escape(curl, clientid, 0);
	escaped_login = curl_easy_escape(curl, username, 0);
	escaped_topic = curl_easy_escape(curl, topic, 0);
	
	size_t params_len = strlen("clientid=&email=&topic=&access=") + strlen(escaped_clientid) + strlen(escaped_login) + strlen(escaped_topic) + strlen(access_name) + 1;
	char* params = NULL;
	if ((params = malloc(params_len)) == NULL)
	{
		mosquitto_log_printf(MOSQ_LOG_WARNING, "failed allocate data memory (%u): %s", params_len, strerror(errno));
#ifdef DEBUG_INFO
		fprintf(stderr, "malloc(): %s [%s, %d]\n", strerror(errno), __FILE__, __LINE__);
#endif
		return MOSQ_ERR_ACL_DENIED;
	} 
	else 
	{
		memset(params, 0, params_len);
		snprintf(params, params_len, "clientid=%s&email=%s&topic=%s&access=%s", escaped_clientid, escaped_login, escaped_topic, access_name);
	}
		
	struct url_data data;
	data.size = 0;
	data.data = malloc(1024);
	if (NULL == data.data) 
	{
		fprintf(stderr, "Failed to allocate memory.\n");
		return MOSQ_ERR_ACL_DENIED;
	}

	data.data[0] = '\0';

	CURLcode res;
	
	curl_easy_setopt(curl, CURLOPT_URL, DEFAULT_ACL_URI);
	curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_data);
	curl_easy_setopt(curl, CURLOPT_FOLLOWLOCATION, 1L);
	curl_easy_setopt(curl, CURLOPT_POSTFIELDS, params);
	curl_easy_setopt(curl, CURLOPT_POSTFIELDSIZE, strlen(params));
	curl_easy_setopt(curl, CURLOPT_WRITEDATA, &data);
	
	res = curl_easy_perform(curl);
	
	if (res != CURLE_OK) 
	{
		fprintf(stderr, "curl_easy_perform() failed: %s\n",  curl_easy_strerror(res));
	}

	curl_easy_cleanup(curl);
	curl_free(escaped_clientid);
	curl_free(escaped_login);
	curl_free(escaped_topic);
	free(params);
	params = NULL;
	
#ifdef DEBUG_INFO
	printf("data.size: %ld bytes\n", data.size);
#endif

	struct json_object *jobj;
	jobj = json_tokener_parse(data.data);
	
#ifdef DEBUG_INFO
	printf("json object from data.data:\n%s\n", json_object_to_json_string_ext(jobj, JSON_C_TO_STRING_SPACED | JSON_C_TO_STRING_PRETTY));
#endif
	
	/*
	 * Parse JSON object below.
	 */
	struct json_object *statusMessage;
	json_object_object_get_ex(jobj, "status", &statusMessage);
	
	// Validate the reply.
	if (strcmp(json_object_get_string(statusMessage), "SUCCESS") == 0)
	{
		json_object_put(jobj);
		free(data.data);
		return MOSQ_ERR_SUCCESS;
	}
	
	json_object_put(jobj);
	free(data.data);
	return MOSQ_ERR_ACL_DENIED;
}

int mosquitto_auth_psk_key_get(void *user_data, struct mosquitto *client, const char *hint, const char *identity, char *key, int max_key_len) 
{
	return MOSQ_ERR_AUTH;
}

