/**
 * MoonUp Solutions - Main JavaScript
 * Handles Meta-grade theme engine, responsive navigation, FAQ accordions,
 * and asynchronous inquiry submissions via FastAPI.
 */

// Immediate Theme Initialization (Defaults to 'dark')
const savedTheme = localStorage.getItem("moonup-theme") || "dark";
document.documentElement.setAttribute("data-theme", savedTheme);

document.addEventListener("DOMContentLoaded", () => {
  // 1. Theme Engine (SVG Icons & State Persistence)
  const themeToggle = document.getElementById("themeToggle");

  const sunSvg = `
    <svg viewBox="0 0 24 24" aria-hidden="true">
      <path d="M12 7c-2.76 0-5 2.24-5 5s2.24 5 5 5 5-2.24 5-5-2.24-5-5-5zM2 13h2c.55 0 1-.45 1-1s-.45-1-1-1H2c-.55 0-1 .45-1 1s.45 1 1 1zm18 0h2c.55 0 1-.45 1-1s-.45-1-1-1h-2c-.55 0-1 .45-1 1s.45 1 1 1zM11 2v2c0 .55.45 1 1 1s1-.45 1-1V2c0-.55-.45-1-1-1s-1 .45-1 1zm0 18v2c0 .55.45 1 1 1s1-.45 1-1v-2c0-.55-.45-1-1-1s-1 .45-1 1zM5.99 4.58c-.39-.39-1.03-.39-1.41 0s-.39 1.03 0 1.41l1.06 1.06c.39.39 1.03.39 1.41 0s.39-1.03 0-1.41L5.99 4.58zm12.37 12.37c-.39-.39-1.03-.39-1.41 0s-.39 1.03 0 1.41l1.06 1.06c.39.39 1.03.39 1.41 0s.39-1.03 0-1.41l-1.06-1.06zm1.06-10.96c.39-.39.39-1.03 0-1.41s-1.03-.39-1.41 0l-1.06 1.06c-.39.39-.39 1.03 0 1.41s1.03.39 1.41 0l1.06-1.06zM7.05 18.36c.39-.39.39-1.03 0-1.41s-1.03-.39-1.41 0l-1.06 1.06c-.39.39-.39 1.03 0 1.41s1.03.39 1.41 0l1.06-1.06z"/>
    </svg>`;

  const moonSvg = `
    <svg viewBox="0 0 24 24" aria-hidden="true">
      <path d="M12.3 2a10 10 0 0 0-.19 2c0 5.52 4.48 10 10 10c.68 0 1.35-.07 2-.19A10 10 0 1 1 12.3 2z"/>
    </svg>`;

  function renderThemeToggle(theme) {
    if (!themeToggle) return;
    themeToggle.innerHTML = theme === "dark" ? sunSvg : moonSvg;
    themeToggle.setAttribute(
      "title",
      theme === "dark" ? "Switch to Light Mode" : "Switch to Dark Mode"
    );
    themeToggle.setAttribute(
      "aria-label",
      theme === "dark" ? "Switch to Light Mode" : "Switch to Dark Mode"
    );
  }

  if (themeToggle) {
    renderThemeToggle(document.documentElement.getAttribute("data-theme") || "dark");

    themeToggle.addEventListener("click", () => {
      const active = document.documentElement.getAttribute("data-theme") || "dark";
      const next = active === "dark" ? "light" : "dark";
      document.documentElement.setAttribute("data-theme", next);
      localStorage.setItem("moonup-theme", next);
      renderThemeToggle(next);
    });
  }

  // 2. Responsive Mobile Drawer Navigation
  const menuToggle = document.querySelector(".menu-toggle");
  const navLinks = document.querySelector(".nav-links");

  if (menuToggle && navLinks) {
    menuToggle.addEventListener("click", () => {
      const isExpanded = menuToggle.getAttribute("aria-expanded") === "true";
      menuToggle.setAttribute("aria-expanded", !isExpanded);
      navLinks.classList.toggle("open");
    });

    navLinks.querySelectorAll("a").forEach((link) => {
      link.addEventListener("click", () => {
        if (navLinks.classList.contains("open")) {
          navLinks.classList.remove("open");
          menuToggle.setAttribute("aria-expanded", "false");
        }
      });
    });

    document.addEventListener("click", (e) => {
      if (
        navLinks.classList.contains("open") &&
        !navLinks.contains(e.target) &&
        !menuToggle.contains(e.target)
      ) {
        navLinks.classList.remove("open");
        menuToggle.setAttribute("aria-expanded", "false");
      }
    });

    document.addEventListener("keydown", (e) => {
      if (e.key === "Escape" && navLinks.classList.contains("open")) {
        navLinks.classList.remove("open");
        menuToggle.setAttribute("aria-expanded", "false");
        menuToggle.focus();
      }
    });
  }

  // 3. FAQ Accordion
  const faqQuestions = document.querySelectorAll(".faq-question");
  faqQuestions.forEach((button) => {
    button.addEventListener("click", () => {
      const item = button.closest(".faq-item");
      const isOpen = item.classList.contains("open");

      document.querySelectorAll(".faq-item").forEach((other) => {
        if (other !== item) other.classList.remove("open");
      });

      item.classList.toggle("open", !isOpen);
    });
  });

  // 4. Pre-select Service Dropdown from URL parameter
  const serviceSelect = document.getElementById("serviceNeeded");
  if (serviceSelect) {
    const urlParams = new URLSearchParams(window.location.search);
    const serviceParam = urlParams.get("service");
    if (serviceParam) {
      const lower = serviceParam.toLowerCase();
      for (const option of serviceSelect.options) {
        if (
          (lower.includes("ai") && option.value.includes("AI")) ||
          (lower.includes("literacy") && option.value.includes("Literacy")) ||
          (lower.includes("project") && option.value.includes("Project")) ||
          (lower.includes("web") && option.value.includes("Web"))
        ) {
          option.selected = true;
          break;
        }
      }
    }
  }

  // 5. Contact Form Submission (Hybrid: Web3Forms for GitHub Pages / FastAPI for Local Dev)
  const contactForm = document.getElementById("contactForm");
  const formAlert = document.getElementById("formAlert");

  const FORM_CONFIG = {
    web3FormsKey: "d0356dc1-8c7a-427b-a251-95ba0f42dade"
  };

  if (contactForm && formAlert) {
    contactForm.addEventListener("submit", async (e) => {
      e.preventDefault();

      const submitBtn = contactForm.querySelector('button[type="submit"]');
      const originalBtnText = submitBtn ? submitBtn.textContent : "Submit";

      const nameInput = document.getElementById("fullName");
      const emailInput = document.getElementById("emailAddress");
      const orgInput = document.getElementById("organization");
      const serviceInput = document.getElementById("serviceNeeded");
      const messageInput = document.getElementById("projectMessage");

      const fullName = nameInput ? nameInput.value.trim() : "";
      const email = emailInput ? emailInput.value.trim() : "";
      const organization = orgInput ? orgInput.value.trim() : "";
      const serviceNeeded = serviceInput ? serviceInput.value.trim() : "";
      const message = messageInput ? messageInput.value.trim() : "";

      if (!fullName || fullName.length < 2) {
        showAlert("error", "Please provide your full name (at least 2 characters).");
        if (nameInput) nameInput.focus();
        return;
      }

      if (!email || !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) {
        showAlert("error", "Please enter a valid email address.");
        if (emailInput) emailInput.focus();
        return;
      }

      if (!message || message.length < 5) {
        showAlert("error", "Please provide project details (at least 5 characters).");
        if (messageInput) messageInput.focus();
        return;
      }

      if (submitBtn) {
        submitBtn.disabled = true;
        submitBtn.textContent = "Submitting...";
      }

      // Check if running on local FastAPI server (http://localhost:8000 or http://127.0.0.1:8000)
      const isLocalFastAPI =
        (window.location.hostname === "localhost" || window.location.hostname === "127.0.0.1") &&
        window.location.port === "8000";

      if (isLocalFastAPI) {
        try {
          const response = await fetch("/api/inquiries", {
            method: "POST",
            headers: {
              "Content-Type": "application/json",
              "Accept": "application/json"
            },
            body: JSON.stringify({
              full_name: fullName,
              email: email,
              organization: organization,
              service_needed: serviceNeeded || "General Inquiry",
              message: message
            })
          });

          const data = await response.json();

          if (response.ok && data.success) {
            showAlert(
              "success",
              `<strong>Thank you, ${escapeHtml(fullName)}!</strong> Your inquiry (#${data.inquiry_id}) has been received. Our team will review your requirements and respond within 24 business hours.`
            );
            contactForm.reset();
            return;
          }
        } catch (localErr) {
          console.log("Local FastAPI endpoint not reachable, dispatching via Web3Forms gateway...", localErr);
        }
      }

      // Production & GitHub Pages: Web3Forms Email Gateway
      try {
        const response = await fetch("https://api.web3forms.com/submit", {
          method: "POST",
          headers: {
            "Content-Type": "application/json",
            "Accept": "application/json"
          },
          body: JSON.stringify({
            access_key: FORM_CONFIG.web3FormsKey,
            subject: `New MoonUp Solutions Inquiry: ${fullName} (${serviceNeeded || "General"})`,
            from_name: "MoonUp Solutions Website",
            name: fullName,
            email: email,
            organization: organization || "N/A",
            service: serviceNeeded || "General Inquiry",
            message: message
          })
        });

        const data = await response.json();

        if (response.ok && data.success) {
          showAlert(
            "success",
            `<strong>Thank you, ${escapeHtml(fullName)}!</strong> Your inquiry has been received. Our team will review your requirements and respond within 24 business hours.`
          );
          contactForm.reset();
        } else {
          showAlert(
            "error",
            data.message || "Unable to submit inquiry at this moment. Please email inquiries@moonupsolutions.com directly."
          );
        }
      } catch (err) {
        console.warn("Submission error:", err);
        showAlert(
          "error",
          "Could not send inquiry. Please check your internet connection or email us at <a href='mailto:inquiries@moonupsolutions.com'>inquiries@moonupsolutions.com</a>."
        );
      } finally {
        if (submitBtn) {
          submitBtn.disabled = false;
          submitBtn.textContent = originalBtnText;
        }
      }
    });
  }

  function showAlert(type, htmlContent) {
    if (!formAlert) return;
    formAlert.style.display = "block";
    formAlert.className = `form-alert ${type}`;
    formAlert.innerHTML = htmlContent;
    formAlert.scrollIntoView({ behavior: "smooth", block: "nearest" });
  }

  function escapeHtml(str) {
    return str
      .replace(/&/g, "&amp;")
      .replace(/</g, "&lt;")
      .replace(/>/g, "&gt;")
      .replace(/"/g, "&quot;")
      .replace(/'/g, "&#039;");
  }
});
