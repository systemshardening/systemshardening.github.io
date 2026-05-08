---
title: "About"
description: "Engineering-first resource for hardening production systems. Practical configurations, explicit trade-offs, and documented failure modes for..."
layout: page.njk
permalink: /about/index.html
published: true
---

# About

systemshardening.com is an engineering-first resource for hardening production systems. Every guide, configuration, and recommendation is written for systems that are already running, serving traffic, processing data, and operating under real constraints.

## What Makes This Different

- **Configurations over concepts.** If it cannot be applied directly, it does not belong here.
- **Trade-offs are explicit.** Security costs something. We tell you what.
- **Failure modes are documented.** We tell you what breaks, why, and how to fix it.
- **Written for production.** Rollback strategies, staged rollouts, and blast radius control are part of every recommendation.

## Who This Is For

- Platform Engineers building [Kubernetes](https://kubernetes.io) clusters and internal platforms
- Site Reliability Engineers who own uptime and incident response
- DevOps Engineers running CI/CD pipelines and automation
- Security Engineers focused on detection and prevention
- Systems Engineers managing OS-level configuration
- AI/ML Platform Engineers deploying models and inference endpoints

## Content Structured for Humans and AI Agents

Every article follows the same six-section structure: Problem, Threat Model, Configuration, Expected Behaviour, Trade-offs, Failure Modes. A senior engineer can scan the headings to find the decision point they care about. An AI agent can locate the Configuration section and find complete, copy-pasteable commands with no pseudocode.

Several machine-readable formats are available for programmatic access:

- **[JSON article index](/api/articles.json)** — structured metadata for every article: title, URL, category, tags, difficulty, estimated reading time, and target personas.
- **[llms.txt](/llms.txt)** — a plain-text index designed for LLM crawlers, listing all categories with article counts and descriptions, plus links to the JSON API and Atom feed. Auto-generated on every build from the live article collection.
- **[Atom feed](/feed.xml)** — full-content feed of all articles, suitable for feed readers and automated pipelines.
- **[Sitemap](/sitemap.xml)** — canonical URLs for every page with last-modified dates.
- **JSON-LD schema** — every article page includes `TechArticle` and `BreadcrumbList` structured data in the page `<head>`, readable by search engines and any tool that parses HTML metadata.
