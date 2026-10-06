// Read-only English public incidents page. Fetches GET /v1/mvp/incidents (no auth)
// and renders published incidents with the "what you should do" action bullets.
(function () {
  'use strict';
  var el = function (tag, className, textContent) {
    var node = document.createElement(tag);
    if (className) node.className = className;
    if (textContent !== undefined && textContent !== null) node.textContent = textContent;
    return node;
  };
  var formatSeverity = function (severity) {
    return severity ? severity.charAt(0).toUpperCase() + severity.slice(1) + ' severity' : 'No severity';
  };
  var render = function (incident) {
    var card = el('article');
    if (incident.level === 'credible_threat' || incident.level === 'confirmed_incident') card.classList.add('top');
    var head = el('p');
    head.append(el('span', 'level', incident.level.replace(/_/g, ' ')));
    head.append(el('span', 'sev', formatSeverity(incident.severity)));
    card.append(head);
    card.append(el('h3', null, incident.title));
    card.append(el('p', 'summary', incident.summary));
    if (Array.isArray(incident.advice) && incident.advice.length) {
      card.append(el('p', 'advice-label', 'What you should do:'));
      var list = el('ul', 'advice');
      incident.advice.forEach(function (item) { list.append(el('li', null, item)); });
      card.append(list);
    }
    var meta = el('p', 'meta', incident.id + ' · updated ' + new Date(incident.updatedAt).toISOString().replace('T', ' ').slice(0, 16) + ' UTC · v' + incident.version);
    card.append(meta);
    if (Array.isArray(incident.evidence) && incident.evidence.length) {
      var ev = el('p', 'evidence');
      ev.append(el('strong', null, 'Selected public sources: '));
      incident.evidence.forEach(function (item, index) {
        if (index) ev.append(document.createTextNode(' · '));
        ev.append(el('span', null, item.kind + ': ' + item.reference));
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
