// Read-only English public incidents page. Fetches GET /v1/mvp/incidents (no auth).
// Mockup-aligned card layout. Uses only PublicIncident fields (no API change).
// Optional: if a seed record includes a non-schema "target" string, it is shown
// as a code-style Target line. Otherwise the line is omitted.
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
    if (incident.level === 'credible_threat' || incident.level === 'confirmed_incident') {
      return 'Approved by 2 of 3 reviewers';
    }
    if (incident.level === 'false_alarm') {
      return 'Closed as false alarm (2 of 3 reviewers)';
    }
    if (incident.approvalMode === 'three_reviewer_quorum') {
      return 'Approved by reviewers';
    }
    return 'Published (demo reviewer)';
  };
  var render = function (incident) {
    var card = el('article', 'incident level-' + incident.level);
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
    if (incident.target) {
      var target = el('p', 'target');
      target.append(document.createTextNode('Target: '));
      target.append(el('code', null, String(incident.target)));
      card.append(target);
    }
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
  }).catch(function () {
    var loading = document.getElementById('loading');
    if (loading) loading.textContent = 'Could not load incidents. Try refreshing the page.';
  });
})();
