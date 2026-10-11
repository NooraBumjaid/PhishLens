(function () {
  "use strict";

  function prefersReducedMotion() {
    return (
      window.matchMedia &&
      window.matchMedia("(prefers-reduced-motion: reduce)").matches
    );
  }

  function onReady(callback) {
    if (document.readyState === "loading") {
      document.addEventListener("DOMContentLoaded", callback);
    } else {
      callback();
    }
  }

  function initMobileNav() {
    var toggle = document.getElementById("nav-toggle");
    var nav = document.getElementById("site-nav");
    if (!toggle || !nav) {
      return;
    }

    toggle.addEventListener("click", function () {
      var open = toggle.getAttribute("aria-expanded") === "true";
      var next = !open;
      toggle.setAttribute("aria-expanded", next ? "true" : "false");
      toggle.setAttribute("aria-label", next ? "Close menu" : "Open menu");
      nav.classList.toggle("is-open", next);
      document.body.classList.toggle("nav-open", next);
    });

    nav.querySelectorAll("a").forEach(function (link) {
      link.addEventListener("click", function () {
        toggle.setAttribute("aria-expanded", "false");
        toggle.setAttribute("aria-label", "Open menu");
        nav.classList.remove("is-open");
        document.body.classList.remove("nav-open");
      });
    });

    document.addEventListener("keydown", function (event) {
      if (event.key === "Escape" && toggle.getAttribute("aria-expanded") === "true") {
        toggle.setAttribute("aria-expanded", "false");
        toggle.setAttribute("aria-label", "Open menu");
        nav.classList.remove("is-open");
        document.body.classList.remove("nav-open");
        toggle.focus();
      }
    });
  }

  function initAnalysisDetails() {
    document.querySelectorAll("details.full-analysis-details").forEach(function (details) {
      details.addEventListener("toggle", function () {
        if (!details.open) {
          return;
        }
        if (prefersReducedMotion()) {
          return;
        }
        details.scrollIntoView({ behavior: "smooth", block: "nearest" });
      });
    });
  }

  function initLoadingForms() {
    document.querySelectorAll("form[method='post']").forEach(function (form) {
      form.addEventListener("submit", function () {
        var button = form.querySelector('button[type="submit"]');
        if (!button || button.disabled) {
          return;
        }
        button.disabled = true;
        button.classList.add("is-loading");
        var loadingText = button.getAttribute("data-loading");
        if (loadingText) {
          button.setAttribute("data-original-label", button.textContent.trim());
          button.textContent = loadingText;
        }
      });
    });
  }

  function initCopyUrlButtons() {
    document.querySelectorAll(".copy-url-button[data-copy-text]").forEach(function (button) {
      button.addEventListener("click", function () {
        var text = button.getAttribute("data-copy-text") || "";
        if (!text) {
          return;
        }

        function markCopied() {
          button.classList.add("is-copied");
          button.setAttribute("aria-label", "Copied full URL");
          window.setTimeout(function () {
            button.classList.remove("is-copied");
            button.setAttribute("aria-label", "Copy full URL " + text);
          }, 1600);
        }

        if (navigator.clipboard && navigator.clipboard.writeText) {
          navigator.clipboard.writeText(text).then(markCopied).catch(function () {
            fallbackCopy(text, markCopied);
          });
        } else {
          fallbackCopy(text, markCopied);
        }
      });

      button.addEventListener("keydown", function (event) {
        if (event.key === "Enter" || event.key === " ") {
          event.preventDefault();
          button.click();
        }
      });
    });
  }

  function fallbackCopy(text, onSuccess) {
    var area = document.createElement("textarea");
    area.value = text;
    area.setAttribute("readonly", "");
    area.style.position = "fixed";
    area.style.left = "-9999px";
    document.body.appendChild(area);
    area.select();
    try {
      if (document.execCommand("copy")) {
        onSuccess();
      }
    } catch (_error) {
      /* Clipboard unavailable; leave button unchanged. */
    }
    document.body.removeChild(area);
  }

  onReady(function () {
    initMobileNav();
    initAnalysisDetails();
    initLoadingForms();
    initCopyUrlButtons();
  });
})();
