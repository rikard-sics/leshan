/*******************************************************************************
 * Copyright (c) 2021 Sierra Wireless and others.
 *
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the Eclipse Public License v2.0
 * and Eclipse Distribution License v1.0 which accompany this distribution.
 *
 * The Eclipse Public License is available at
 *    http://www.eclipse.org/legal/epl-v20.html
 * and the Eclipse Distribution License is available at
 *    http://www.eclipse.org/org/documents/edl-v10.html.
 *******************************************************************************/

"use strict";

import axios from "axios";

// Full config:  https://github.com/axios/axios#request-config
// axios.defaults.baseURL = process.env.baseURL || process.env.apiUrl || '';
// axios.defaults.headers.common['Authorization'] = AUTH_TOKEN;
// axios.defaults.headers.post['Content-Type'] = 'application/x-www-form-urlencoded';

let config = {
  // baseURL: process.env.baseURL || process.env.apiUrl || ""
  // timeout: 60 * 1000, // Timeout
  // withCredentials: true, // Check cross-site Access-Control
  responseType: "json",
};

// HACK waiting we get a solution for : https://github.com/yariksav/vuetify-dialog/issues/110#issuecomment-1145981361
// and unfortenately there is not standard way to do that ... : https://stackoverflow.com/questions/40263803/native-javascript-or-es6-way-to-encode-and-decode-html-entities
const escapeHTML = (str) =>
  str;
// str.replace(
//   /[&<>'"]/g,
//   (tag) =>
//   ({
//     "&": "&amp;",
//     "<": "&lt;",
//     ">": "&gt;",
//     "'": "&#39;",
//     '"': "&quot;",
//   }[tag])
//);

const _axios = axios.create(config);

_axios.interceptors.request.use(
  function (config) {
    // Do something before request is sent
    return config;
  },
  function (error) {
    // Do something with request error
    return Promise.reject(error);
  }
);

// Add a response interceptor
_axios.interceptors.response.use(
  function (response) {
    // show error message if device return a failure code
    if (response.data && response.data.failure) {
      let msg = `Device response : ${response.data.status}`;
      if (response.data.errormessage) msg += ` - ${response.data.errormessage}`;
      _axios.$notify.warn(escapeHTML(msg), {
        location: "bottom right",
        timeout: 5000,
      });
    }
    return response;
  },
  function (error) {
    let message;
    if (error.response) {
      console.log(
        `${error.message}[${error.response.status}], full error :`,
        error
      );
      if (typeof error.response.data == "string" && error.response.data !== "") {
        message = error.response.data;
      } else if (
        typeof error.response.data == "object" &&
        typeof error.response.data.message == "string" && error.response.data.message !== ""
      ) {
        message = error.response.data.message;
      } else {
        message = error.message;
      }
    } else if (error.request) {
      console.log(`${error.message}:, full error :`, error);
      message =
        typeof error.request.data == "string" && error.request.data !== ""
          ? error.request.data
          : error.message;
    } else {
      console.log(`${error.message}:, full error :`, error);
      message = error.message;
    }
    console.log(message)
    _axios.$notify.error(message, {
      location: "bottom right",
      timeout: 5000,
    });
    return Promise.reject(error);
  }
);


export default {
  install: (app) => {
    _axios.$notify = app.config.globalProperties.$notify;
    app.config.globalProperties.axios = _axios;
    app.config.globalProperties.$axios = _axios;
  }
}
