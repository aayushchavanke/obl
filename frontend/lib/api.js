"use client";

const envBase = process.env.NEXT_PUBLIC_API_BASE_URL?.trim();

function normalizeBaseUrl(value) {
  return value ? value.replace(/\/+$/, "") : "";
}

function inferBrowserBaseUrl() {
  if (typeof window === "undefined") {
    return "http://127.0.0.1:5000";
  }

  const { protocol, hostname } = window.location;
  return `${protocol}//${hostname}:5000`;
}

export const API_BASE_URL = normalizeBaseUrl(envBase) || inferBrowserBaseUrl();

