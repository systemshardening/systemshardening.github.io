(function () {
  "use strict";

  var searchData = [];
  var debounceTimer = null;
  var input = document.getElementById("article-search");

  if (!input) return;

  fetch("/search-data.json")
    .then(function (res) { return res.json(); })
    .then(function (data) { searchData = data; })
    .catch(function () { searchData = []; });

  input.addEventListener("input", function () {
    clearTimeout(debounceTimer);
    debounceTimer = setTimeout(performSearch, 150);
  });

  function performSearch() {
    var query = input.value.trim().toLowerCase();
    var cards = document.querySelectorAll(".article-card");

    if (!query) {
      cards.forEach(function (card) { card.classList.remove("hidden"); });
      document.querySelectorAll(".category-section").forEach(function (sec) {
        sec.classList.remove("hidden");
      });
      return;
    }

    var matchedUrls = {};
    searchData.forEach(function (item) {
      var haystack = (item.title + " " + item.category + " " + (item.tags || []).join(" ")).toLowerCase();
      if (haystack.indexOf(query) !== -1) {
        matchedUrls[item.url] = true;
      }
    });

    cards.forEach(function (card) {
      var link = card.querySelector("h3 a, a h3");
      if (!link) link = card.querySelector("a");
      var href = link ? link.getAttribute("href") : "";

      var titleEl = card.querySelector("h3");
      var catEl = card.querySelector(".article-category");
      var tagEls = card.querySelectorAll(".tag");

      var cardText = "";
      if (titleEl) cardText += titleEl.textContent + " ";
      if (catEl) cardText += catEl.textContent + " ";
      tagEls.forEach(function (t) { cardText += t.textContent + " "; });
      cardText = cardText.toLowerCase();

      var matched = cardText.indexOf(query) !== -1 || matchedUrls[href];
      if (matched) {
        card.classList.remove("hidden");
      } else {
        card.classList.add("hidden");
      }
    });

    document.querySelectorAll(".category-section").forEach(function (sec) {
      var visibleCards = sec.querySelectorAll(".article-card:not(.hidden)");
      if (visibleCards.length === 0) {
        sec.classList.add("hidden");
      } else {
        sec.classList.remove("hidden");
      }
    });
  }
})();
