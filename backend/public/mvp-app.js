// Read-only English public incidents page. Fetches GET /v1/mvp/incidents (no auth).
// Mockup-aligned card layout. Uses only PublicIncident fields (no API change).
(function () {
  'use strict';
  var el = function (tag, className, textContent) {
    var node = document.createElement(tag);
    if (className) node.className = className;
    if (textContent !== undefined && textContent !== null) node.textContent = textContent;
    return node;
  };
  var formatLevel = function (level) {
    return String(level).replace(/_/g, ' ').replace(/\b\w/g, function (c) { return c.toUpperCase(); });
  };
  var formatSeverityPill = function (severity) {
    if (!severity) return null;
    return 'Severity: ' + severity.charAt(0).toUpperCase() + severity.slice(1);
  };
  var formatDate = function (iso) {
    try {
      var d = new Date(iso);
      if (isNaN(d.getTime())) return '';
      return d.toLocaleDateString('en-GB', { day: 'numeric', month: 'short', year: 'numeric' });
    } catch (e) {
      return '';
    }
  };
  var approvalLine = function (incident) {
    // Ollie 2026-10-18: show the real approval counts, not a hardcoded 2 of 3.
    var counts = function () {
      if (!incident.approvalCount || !incident.requiredApprovals) return null;
      return incident.approvalCount + ' of ' + incident.requiredApprovals;
    };
    if (incident.level === 'credible_threat' || incident.level === 'confirmed_incident') {
      var approved = counts();
      return approved ? 'Approved by ' + approved + ' reviewers' : 'Approved by reviewers';
    }
    if (incident.level === 'false_alarm') {
      var closed = counts();
      return closed ? 'Closed as false alarm (' + closed + ' reviewers)' : 'Closed as false alarm';
    }
    if (incident.level === 'resolved') {
      return 'Closed as resolved';
    }
    if (incident.approvalMode === 'three_reviewer_quorum') {
      return 'Approved by reviewers';
    }
    return 'Published (demo reviewer)';
  };
  var render = function (incident) {
    var card = el('article', 'incident level-' + incident.level);
    card.id = incident.id; // anchor target for /v1/check incidentUrl (#SEN-####)
    var top = el('div', 'card-top');
    var pills = el('div', 'pills');
    pills.append(el('span', 'pill id', incident.id));
    pills.append(el('span', 'pill level-' + incident.level, formatLevel(incident.level)));
    var sevText = formatSeverityPill(incident.severity);
    if (sevText) pills.append(el('span', 'pill sev-' + incident.severity, sevText));
    top.append(pills);
    var date = formatDate(incident.publishedAt || incident.updatedAt);
    if (date) top.append(el('span', 'date', date));
    card.append(top);
    card.append(el('h3', null, incident.title));
    if (incident.summary) card.append(el('p', 'summary', incident.summary));
    if (Array.isArray(incident.advice) && incident.advice.length) {
      card.append(el('p', 'advice-label', 'What you should do'));
      var list = el('ul', 'advice');
      incident.advice.forEach(function (item) { list.append(el('li', null, item)); });
      card.append(list);
    }
    card.append(el('p', 'approved', approvalLine(incident)));
    if (Array.isArray(incident.evidence) && incident.evidence.length) {
      var ev = el('p', 'evidence');
      ev.append(el('strong', null, 'Selected public sources: '));
      incident.evidence.forEach(function (item, index) {
        if (index) ev.append(document.createTextNode(' · '));
        ev.append(document.createTextNode(item.kind + ': ' + item.reference));
      });
      card.append(ev);
    }
    return card;
  };
  fetch('/v1/mvp/incidents').then(function (res) {
    if (!res.ok) throw new Error('HTTP ' + res.status);
    return res.json();
  }).then(function (data) {
    var section = document.getElementById('incidents');
    var loading = document.getElementById('loading');
    if (loading) loading.remove();
    var incidents = (data && data.incidents) || [];
    if (!incidents.length) {
      section.append(el('p', 'muted', 'No incidents have been published yet.'));
      return;
    }
    incidents.forEach(function (incident) { section.append(render(incident)); });
    // Scroll to and highlight an incident referenced via #SEN-#### (used by the
    // check API's incidentUrl so agents can link straight to the warning).
    var jump = function () {
      var id = window.location.hash.slice(1);
      if (!id) return;
      var card = document.getElementById(id);
      if (!card) return;
      card.scrollIntoView();
      card.classList.add('anchor-target');
    };
    if (window.location.hash) jump();
    window.addEventListener('hashchange', jump);
  }).catch(function () {
    var loading = document.getElementById('loading');
    if (loading) loading.textContent = 'Could not load incidents. Try refreshing the page.';
  });
})();
