const markdownIt = require("markdown-it");
const markdownItAnchor = require("markdown-it-anchor");

module.exports = function (eleventyConfig) {
  // Markdown configuration
  const md = markdownIt({
    html: true,
    linkify: true,
    typographer: true,
  }).use(markdownItAnchor, {
    permalink: markdownItAnchor.permalink.headerLink(),
    level: 2,
  });

  // Open external links in new tab
  const defaultRender = md.renderer.rules.link_open || function(tokens, idx, options, env, self) {
    return self.renderToken(tokens, idx, options);
  };
  md.renderer.rules.link_open = function(tokens, idx, options, env, self) {
    const href = tokens[idx].attrGet("href");
    if (href && href.startsWith("http")) {
      tokens[idx].attrSet("target", "_blank");
      tokens[idx].attrSet("rel", "noopener");
    }
    return defaultRender(tokens, idx, options, env, self);
  };

  eleventyConfig.setLibrary("md", md);

  // Don't use .gitignore for ignoring files (we need src/content/ which is gitignored)
  eleventyConfig.setUseGitIgnore(false);

  // Manually ignore node_modules and dist
  eleventyConfig.ignores.add("node_modules");

  // Current year for copyright
  eleventyConfig.addShortcode("year", () => `${new Date().getFullYear()}`);

  // Pass through static assets
  eleventyConfig.addPassthroughCopy({ "public": "/" });

  // Collection: all articles (sorted by date, newest first)
  eleventyConfig.addCollection("articles", function (collectionApi) {
    return collectionApi
      .getFilteredByGlob("src/content/articles/**/*.md")
      .filter((item) => item.data.published !== false)
      .sort((a, b) => (b.data.date || 0) - (a.data.date || 0));
  });

  // Collection: articles grouped by category
  eleventyConfig.addCollection("articlesByCategory", function (collectionApi) {
    const articles = collectionApi
      .getFilteredByGlob("src/content/articles/**/*.md")
      .filter((item) => item.data.published !== false);

    const categories = {};
    for (const article of articles) {
      const cat = article.data.category || "uncategorized";
      if (!categories[cat]) categories[cat] = [];
      categories[cat].push(article);
    }

    // Sort articles within each category by date
    for (const cat of Object.keys(categories)) {
      categories[cat].sort((a, b) => (b.data.date || 0) - (a.data.date || 0));
    }

    return categories;
  });

  // Collection: static pages
  eleventyConfig.addCollection("pages", function (collectionApi) {
    return collectionApi
      .getFilteredByGlob("src/content/pages/*.md")
      .filter((item) => item.data.published !== false);
  });

  // Filter: format date
  eleventyConfig.addFilter("dateDisplay", function (date) {
    if (!date) return "";
    const d = new Date(date);
    return d.toLocaleDateString("en-GB", {
      year: "numeric",
      month: "long",
      day: "numeric",
    });
  });

  // Filter: reading time
  eleventyConfig.addFilter("readingTime", function (content) {
    if (!content) return "0 min";
    const words = content.split(/\s+/).length;
    const minutes = Math.ceil(words / 200);
    return `${minutes} min read`;
  });

  // Filter: convert date to ISO 8601 string (for feeds, sitemaps, JSON)
  eleventyConfig.addFilter("dateToISO", function (date) {
    if (!date) return "";
    return new Date(date).toISOString();
  });

  // Filter: serialize value as JSON string (for JSON templates)
  eleventyConfig.addFilter("jsonStringify", function (value) {
    return JSON.stringify(value);
  });

  // Shortcode: current ISO date (for generated timestamps)
  eleventyConfig.addShortcode("currentDate", function () {
    return new Date().toISOString();
  });

  // Filter: escape for XML (for Atom feed)
  eleventyConfig.addFilter("escape", function (str) {
    if (!str) return "";
    return String(str)
      .replace(/&/g, "&amp;")
      .replace(/</g, "&lt;")
      .replace(/>/g, "&gt;")
      .replace(/"/g, "&quot;");
  });

  // Filter: strip HTML tags (supplement to Nunjucks built-in striptags)
  eleventyConfig.addFilter("striptags", function (str) {
    if (!str) return "";
    return String(str).replace(/<[^>]*>/g, "");
  });

  // Filter: category display name
  eleventyConfig.addFilter("categoryName", function (slug) {
    const names = {
      "linux": "Linux / OS Hardening",
      "kubernetes": "Kubernetes / Platform",
      "network": "Network & API Security",
      "cicd": "CI/CD & Supply Chain",
      "observability": "Observability & Detection",
      "ai-landscape": "AI & Security Landscape",
      "cross-cutting": "Cross-Cutting Guides",
      "wasm": "WebAssembly",
    };
    return names[slug] || slug;
  });

  return {
    dir: {
      input: "src",
      includes: "includes",
      layouts: "layouts",
      output: "dist",
      data: "data",
    },
    markdownTemplateEngine: false,  // Don't process {{ }} in Markdown files
    htmlTemplateEngine: "njk",
  };
};
