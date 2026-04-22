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

  eleventyConfig.setLibrary("md", md);

  // Don't use .gitignore for ignoring files (we need src/content/ which is gitignored)
  eleventyConfig.setUseGitIgnore(false);

  // Manually ignore node_modules and dist
  eleventyConfig.ignores.add("node_modules");

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
