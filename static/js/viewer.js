/**
 * WRS Recovery Viewer — Single-Page Interactive Application
 * Local-only, zero-external-dependency forensic data viewer & download center.
 */

(function () {
  'use strict';

  // State
  const state = {
    session: null,
    sessionsList: [],
    files: [],
    filteredFiles: [],
    selectedIds: new Set(),
    activeTab: 'overview',
    searchQuery: '',
    statusFilter: 'all',
    categoryFilter: 'all',
    sortBy: 'name_asc',
    currentImageIndex: -1,
    currentPreviewFile: null,
  };

  // DOM Elements
  const elements = {
    sessionSelect: document.getElementById('sessionSelect'),
    devicePill: document.getElementById('devicePill'),
    connectionStatusPill: document.getElementById('connectionStatusPill'),
    navTabs: document.getElementById('navTabs'),
    tabOverview: document.getElementById('tabOverview'),
    tabGallery: document.getElementById('tabGallery'),
    galleryGrid: document.getElementById('galleryGrid'),
    galleryTitle: document.getElementById('galleryTitle'),
    searchInput: document.getElementById('searchInput'),
    statusFilter: document.getElementById('statusFilter'),
    categoryFilter: document.getElementById('categoryFilter'),
    sortSelect: document.getElementById('sortSelect'),
    selectAllBtn: document.getElementById('selectAllBtn'),
    clearFilterBtn: document.getElementById('clearFilterBtn'),
    floatingBar: document.getElementById('floatingBar'),
    selectionCountLabel: document.getElementById('selectionCountLabel'),
    downloadSelectedBtn: document.getElementById('downloadSelectedBtn'),
    downloadAllBtn: document.getElementById('downloadAllBtn'),
    clearSelectionBtn: document.getElementById('clearSelectionBtn'),
    // Modals
    previewModal: document.getElementById('previewModal'),
    modalTitle: document.getElementById('modalTitle'),
    modalBody: document.getElementById('modalBody'),
    modalDownloadBtn: document.getElementById('modalDownloadBtn'),
    modalCloseBtn: document.getElementById('modalCloseBtn'),
    toastContainer: document.getElementById('toastContainer'),
  };

  // Utilities
  function escapeHtml(str) {
    if (!str) return '';
    return String(str)
      .replace(/&/g, '&amp;')
      .replace(/</g, '&lt;')
      .replace(/>/g, '&gt;')
      .replace(/"/g, '&quot;')
      .replace(/'/g, '&#039;');
  }

  function formatBytes(bytes) {
    if (!bytes || bytes <= 0) return '0 B';
    const units = ['B', 'KiB', 'MiB', 'GiB', 'TiB'];
    const i = Math.floor(Math.log(bytes) / Math.log(1024));
    return (bytes / Math.pow(1024, i)).toFixed(2) + ' ' + units[i];
  }

  function showToast(message, type = 'info') {
    const toast = document.createElement('div');
    toast.className = 'toast';
    toast.innerHTML = `<span>⚡</span> <span>${escapeHtml(message)}</span>`;
    elements.toastContainer.appendChild(toast);
    setTimeout(() => {
      toast.style.opacity = '0';
      setTimeout(() => toast.remove(), 300);
    }, 4000);
  }

  // API Client
  async function fetchStatus() {
    try {
      const res = await fetch('/api/status');
      if (!res.ok) throw new Error('Failed to load status');
      state.session = await res.json();
      updateHeaderMetadata();
    } catch (e) {
      console.error(e);
      showToast('Error loading runtime status: ' + e.message, 'error');
    }
  }

  async function fetchSessions() {
    try {
      const res = await fetch('/api/sessions');
      if (!res.ok) throw new Error('Failed to load sessions');
      const data = await res.json();
      state.sessionsList = data.sessions || [];
      renderSessionSelect(data.active_session_id);
    } catch (e) {
      console.error(e);
    }
  }

  async function fetchFiles() {
    try {
      const res = await fetch('/api/files');
      if (!res.ok) throw new Error('Failed to load file index');
      const data = await res.json();
      state.files = data.files || [];
      updateTabBadges();
      applyFilters();
    } catch (e) {
      console.error(e);
      showToast('Error loading file inventory: ' + e.message, 'error');
    }
  }

  async function selectSession(sessionId) {
    try {
      const res = await fetch('/api/sessions/select', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ session_id: sessionId }),
      });
      if (!res.ok) throw new Error('Failed to select session');
      state.selectedIds.clear();
      await fetchStatus();
      await fetchFiles();
      showToast('Loaded session: ' + sessionId);
    } catch (e) {
      showToast('Failed to switch session: ' + e.message, 'error');
    }
  }

  // Header & Session Select
  function updateHeaderMetadata() {
    if (!state.session) return;
    const s = state.session;
    elements.devicePill.innerHTML = `Device: <strong>${escapeHtml(s.device_name || 'None')}</strong>`;
    elements.connectionStatusPill.innerHTML = `<span class="status-dot ${s.device_status === 'device' ? '' : 'warning'}"></span> <span>${escapeHtml(s.device_status || 'Disconnected')}</span>`;
  }

  function renderSessionSelect(activeId) {
    elements.sessionSelect.innerHTML = '';
    state.sessionsList.forEach((s) => {
      const opt = document.createElement('option');
      opt.value = s.session_id;
      opt.textContent = `${s.session_name} (${s.file_count} files, ${s.total_size_human})`;
      if (s.session_id === activeId) opt.selected = true;
      elements.sessionSelect.appendChild(opt);
    });
  }

  // Tab Navigation
  function updateTabBadges() {
    const counts = {
      all: state.files.length,
      images: state.files.filter((f) => f.category === 'Images').length,
      videos: state.files.filter((f) => f.category === 'Videos').length,
      audio: state.files.filter((f) => f.category === 'Audio').length,
      documents: state.files.filter((f) => f.category === 'Documents').length,
      databases: state.files.filter((f) => f.category === 'Databases').length,
    };

    document.querySelectorAll('.tab-btn').forEach((btn) => {
      const tab = btn.dataset.tab;
      const badge = btn.querySelector('.tab-badge');
      if (badge && counts[tab] !== undefined) {
        badge.textContent = counts[tab];
      }
    });
  }

  function switchTab(targetTab) {
    state.activeTab = targetTab;
    document.querySelectorAll('.tab-btn').forEach((btn) => {
      btn.classList.toggle('active', btn.dataset.tab === targetTab);
    });

    if (targetTab === 'overview') {
      elements.tabOverview.style.display = 'block';
      elements.tabGallery.style.display = 'none';
      renderOverviewDashboard();
    } else {
      elements.tabOverview.style.display = 'none';
      elements.tabGallery.style.display = 'block';

      // Set category filter automatically depending on tab
      const catMap = {
        images: 'Images',
        videos: 'Videos',
        audio: 'Audio',
        documents: 'Documents',
        databases: 'Databases',
        all: 'all',
      };
      if (catMap[targetTab]) {
        state.categoryFilter = catMap[targetTab];
        elements.categoryFilter.value = state.categoryFilter;
      }
      applyFilters();
    }
  }

  // Overview Dashboard
  function renderOverviewDashboard() {
    const s = state.session || {};
    const imgCount = state.files.filter((f) => f.category === 'Images').length;
    const vidCount = state.files.filter((f) => f.category === 'Videos').length;
    const audCount = state.files.filter((f) => f.category === 'Audio').length;
    const docCount = state.files.filter((f) => f.category === 'Documents').length;
    const encDbCount = state.files.filter((f) => f.is_encrypted).length;
    const sqliteCount = state.files.filter((f) => f.is_sqlite && !f.is_encrypted).length;

    const grid = document.getElementById('overviewMetricsGrid');
    grid.innerHTML = `
      <div class="metric-card">
        <div class="metric-title">Discovered Candidates</div>
        <div class="metric-value">${s.total_discovered || state.files.length}</div>
        <div class="metric-subtitle">Identified across scan scope</div>
      </div>
      <div class="metric-card">
        <div class="metric-title">Accessible Files</div>
        <div class="metric-value">${s.total_accessible || state.files.filter((f) => f.is_accessible).length}</div>
        <div class="metric-subtitle">Currently readable / acquirable</div>
      </div>
      <div class="metric-card">
        <div class="metric-title">Acquired Locally</div>
        <div class="metric-value" style="color: var(--status-green);">${s.total_acquired || state.files.filter((f) => f.acquisition_status === 'ACQUIRED').length}</div>
        <div class="metric-subtitle">Stored in local recovery folder</div>
      </div>
      <div class="metric-card">
        <div class="metric-title">Total Indexed Size</div>
        <div class="metric-value" style="color: var(--accent-cyan);">${s.total_size_human || '0 B'}</div>
        <div class="metric-subtitle">${(s.total_size_bytes || 0).toLocaleString()} bytes</div>
      </div>
      <div class="metric-card">
        <div class="metric-title">Images</div>
        <div class="metric-value">${imgCount}</div>
        <div class="metric-subtitle">JPEG, PNG, WebP attachments</div>
      </div>
      <div class="metric-card">
        <div class="metric-title">Videos</div>
        <div class="metric-value">${vidCount}</div>
        <div class="metric-subtitle">MP4, 3GP video records</div>
      </div>
      <div class="metric-card">
        <div class="metric-title">Audio & Voice Notes</div>
        <div class="metric-value">${audCount}</div>
        <div class="metric-subtitle">Opus, M4A, MP3 recordings</div>
      </div>
      <div class="metric-card">
        <div class="metric-title">Documents</div>
        <div class="metric-value">${docCount}</div>
        <div class="metric-subtitle">PDF, Office, Text files</div>
      </div>
      <div class="metric-card">
        <div class="metric-title">Encrypted Databases</div>
        <div class="metric-value" style="color: var(--status-yellow);">${encDbCount}</div>
        <div class="metric-subtitle">Crypt14/15 backup containers</div>
      </div>
      <div class="metric-card">
        <div class="metric-title">Readable Databases</div>
        <div class="metric-value" style="color: var(--accent-blue);">${sqliteCount}</div>
        <div class="metric-subtitle">Unencrypted / Decrypted SQLite</div>
      </div>
    `;

    document.getElementById('overviewSessionProvenance').innerHTML = `
      <p><strong>Active Session Directory:</strong> <code>${escapeHtml(s.session_dir || 'In-Memory Scan Results')}</code></p>
      <p><strong>Device Provenance:</strong> ${escapeHtml(s.device_name || 'None')} (${escapeHtml(s.device_serial || 'None')})</p>
      <p><strong>Last Discovery / Acquisition Time:</strong> ${escapeHtml(s.timestamp || 'N/A')}</p>
    `;
  }

  // Filters & Search
  function applyFilters() {
    let list = [...state.files];

    // Category filter
    if (state.categoryFilter !== 'all') {
      list = list.filter((f) => f.category === state.categoryFilter);
    }

    // Status filter
    if (state.statusFilter !== 'all') {
      if (state.statusFilter === 'acquired') {
        list = list.filter((f) => f.acquisition_status === 'ACQUIRED');
      } else if (state.statusFilter === 'discovered') {
        list = list.filter((f) => f.acquisition_status === 'DISCOVERED');
      } else if (state.statusFilter === 'verified') {
        list = list.filter((f) => f.verification_status === 'VERIFIED');
      } else if (state.statusFilter === 'failed') {
        list = list.filter((f) => f.acquisition_status === 'FAILED');
      } else if (state.statusFilter === 'encrypted') {
        list = list.filter((f) => f.is_encrypted);
      } else if (state.statusFilter === 'readable') {
        list = list.filter((f) => f.is_sqlite && !f.is_encrypted);
      }
    }

    // Search query
    if (state.searchQuery.trim()) {
      const q = state.searchQuery.trim().toLowerCase();
      list = list.filter((f) => f.filename.toLowerCase().includes(q) || (f.source_location && f.source_location.toLowerCase().includes(q)));
    }

    // Sort
    if (state.sortBy === 'name_asc') {
      list.sort((a, b) => a.filename.localeCompare(b.filename));
    } else if (state.sortBy === 'name_desc') {
      list.sort((a, b) => b.filename.localeCompare(a.filename));
    } else if (state.sortBy === 'size_desc') {
      list.sort((a, b) => b.size_bytes - a.size_bytes);
    } else if (state.sortBy === 'size_asc') {
      list.sort((a, b) => a.size_bytes - b.size_bytes);
    } else if (state.sortBy === 'time_desc') {
      list.sort((a, b) => (b.modified_time || '').localeCompare(a.modified_time || ''));
    }

    state.filteredFiles = list;
    renderGallery();
    updateFloatingBar();
  }

  // Gallery Rendering
  function renderGallery() {
    const grid = elements.galleryGrid;
    grid.innerHTML = '';

    const count = state.filteredFiles.length;
    elements.galleryTitle.textContent = `${state.categoryFilter === 'all' ? 'All Files' : state.categoryFilter} (${count})`;

    if (count === 0) {
      grid.innerHTML = `
        <div class="empty-state" style="grid-column: 1 / -1;">
          <div class="empty-state-icon">📁</div>
          <h3>No matching files found</h3>
          <p>No files match the currently selected category, status, or search filters.</p>
          <button class="action-btn" id="resetFiltersEmptyBtn">Reset Filters</button>
        </div>
      `;
      const btn = document.getElementById('resetFiltersEmptyBtn');
      if (btn) btn.onclick = resetFilters;
      return;
    }

    state.filteredFiles.forEach((file) => {
      const card = createCardElement(file);
      grid.appendChild(card);
    });
  }

  function createCardElement(file) {
    const card = document.createElement('div');
    card.className = `file-card ${state.selectedIds.has(file.id) ? 'selected' : ''}`;
    card.id = `card_${file.id}`;

    // Badge styling
    let badgeClass = 'badge-discovered';
    let statusText = file.acquisition_status;
    if (file.is_encrypted) {
      badgeClass = 'badge-encrypted';
      statusText = 'ENCRYPTED';
    } else if (file.acquisition_status === 'ACQUIRED') {
      badgeClass = 'badge-acquired';
      if (file.verification_status === 'VERIFIED') statusText = 'VERIFIED';
    } else if (file.acquisition_status === 'FAILED') {
      badgeClass = 'badge-failed';
    }

    // Thumbnail / Icon
    let thumbHtml = '';
    if (file.preview_type === 'image' && file.has_local_file) {
      thumbHtml = `<img class="thumb-img" src="/api/files/${encodeURIComponent(file.id)}/preview" loading="lazy" alt="${escapeHtml(file.filename)}" onerror="this.onerror=null;this.parentElement.innerHTML='<div class=\\'card-icon-placeholder\\'>🖼️<span style=\\'font-size:0.75rem;\\'>Image</span></div>';">`;
    } else {
      let icon = '📄';
      if (file.preview_type === 'video') icon = '🎬';
      else if (file.preview_type === 'audio') icon = '🎵';
      else if (file.preview_type === 'database') icon = '🗄️';
      else if (file.preview_type === 'pdf') icon = '📑';
      thumbHtml = `<div class="card-icon-placeholder"><span style="font-size: 2.5rem;">${icon}</span><span style="font-size: 0.75rem; color: var(--text-muted);">${escapeHtml(file.category)}</span></div>`;
    }

    card.innerHTML = `
      <div class="card-select-overlay">
        <input type="checkbox" class="card-checkbox" data-id="${escapeHtml(file.id)}" ${state.selectedIds.has(file.id) ? 'checked' : ''} aria-label="Select ${escapeHtml(file.filename)}">
      </div>
      <div class="card-preview-thumb">
        ${thumbHtml}
      </div>
      <div class="card-body">
        <div>
          <div class="card-filename" title="${escapeHtml(file.filename)}">${escapeHtml(file.filename)}</div>
          <div class="card-meta-line">
            <span>${escapeHtml(file.category)}</span>
            <span>${escapeHtml(file.size_human)}</span>
          </div>
          <div>
            <span class="card-status-badge ${badgeClass}">${escapeHtml(statusText)}</span>
          </div>
        </div>
        <div class="card-actions">
          <button class="btn-sm preview-btn" data-id="${escapeHtml(file.id)}">👁️ Preview</button>
          <a class="btn-sm download-btn" href="/api/files/${encodeURIComponent(file.id)}/download" download="${escapeHtml(file.filename)}">⬇ Download</a>
        </div>
      </div>
    `;

    // Checkbox event
    const chk = card.querySelector('.card-checkbox');
    chk.addEventListener('change', (e) => {
      toggleSelect(file.id, e.target.checked);
    });

    // Preview event
    const prevBtn = card.querySelector('.preview-btn');
    prevBtn.addEventListener('click', () => {
      openPreviewModal(file);
    });

    return card;
  }

  // Selection Logic
  function toggleSelect(fileId, isSelected) {
    if (isSelected) {
      state.selectedIds.add(fileId);
    } else {
      state.selectedIds.delete(fileId);
    }

    const card = document.getElementById(`card_${fileId}`);
    if (card) card.classList.toggle('selected', isSelected);
    updateFloatingBar();
  }

  function selectAllFiltered() {
    state.filteredFiles.forEach((f) => state.selectedIds.add(f.id));
    renderGallery();
    updateFloatingBar();
  }

  function clearSelection() {
    state.selectedIds.clear();
    renderGallery();
    updateFloatingBar();
  }

  function updateFloatingBar() {
    const selCount = state.selectedIds.size;
    if (selCount > 0) {
      let totalBytes = 0;
      state.files.forEach((f) => {
        if (state.selectedIds.has(f.id)) totalBytes += f.size_bytes;
      });
      elements.selectionCountLabel.textContent = `Selected: ${selCount} files (${formatBytes(totalBytes)})`;
      elements.floatingBar.classList.add('active');
    } else {
      elements.floatingBar.classList.remove('active');
    }
  }

  function resetFilters() {
    state.searchQuery = '';
    state.statusFilter = 'all';
    state.categoryFilter = 'all';
    state.sortBy = 'name_asc';
    elements.searchInput.value = '';
    elements.statusFilter.value = 'all';
    elements.categoryFilter.value = 'all';
    elements.sortSelect.value = 'name_asc';
    applyFilters();
  }

  // Modals & Preview Logic
  function openPreviewModal(file) {
    state.currentPreviewFile = file;
    elements.modalTitle.textContent = file.filename;
    elements.modalDownloadBtn.href = `/api/files/${encodeURIComponent(file.id)}/download`;
    elements.modalDownloadBtn.setAttribute('download', file.filename);

    const body = elements.modalBody;
    body.innerHTML = '<div style="text-align: center; padding: 2rem;">Loading preview...</div>';
    elements.previewModal.classList.add('open');

    const ptype = file.preview_type;

    if (ptype === 'image') {
      renderImageModal(file, body);
    } else if (ptype === 'audio') {
      renderAudioModal(file, body);
    } else if (ptype === 'video') {
      renderVideoModal(file, body);
    } else if (ptype === 'text') {
      renderTextModal(file, body);
    } else if (ptype === 'pdf') {
      renderPdfModal(file, body);
    } else if (ptype === 'database') {
      renderDatabaseModal(file, body);
    } else {
      renderUnsupportedModal(file, body);
    }
  }

  function closePreviewModal() {
    elements.previewModal.classList.remove('open');
    elements.modalBody.innerHTML = '';
    state.currentPreviewFile = null;
  }

  function renderImageModal(file, container) {
    const images = state.filteredFiles.filter((f) => f.preview_type === 'image');
    state.currentImageIndex = images.findIndex((f) => f.id === file.id);

    container.innerHTML = `
      <div class="image-viewport">
        <button class="modal-nav-btn prev" id="imgPrevBtn" aria-label="Previous image">‹</button>
        <img id="modalPreviewImg" src="/api/files/${encodeURIComponent(file.id)}/preview" alt="${escapeHtml(file.filename)}">
        <button class="modal-nav-btn next" id="imgNextBtn" aria-label="Next image">›</button>
      </div>
      <div style="margin-top: 1rem; display: flex; justify-content: space-between; font-size: 0.85rem; color: var(--text-secondary);">
        <span>Size: <strong>${escapeHtml(file.size_human)}</strong></span>
        <span>Status: <strong style="color: var(--status-green);">${escapeHtml(file.acquisition_status)}</strong></span>
        <span>SHA-256: <code>${file.sha256 ? escapeHtml(file.sha256.substring(0, 16)) + '...' : 'Not calculated'}</code></span>
      </div>
    `;

    document.getElementById('imgPrevBtn').onclick = () => {
      if (images.length === 0) return;
      state.currentImageIndex = (state.currentImageIndex - 1 + images.length) % images.length;
      openPreviewModal(images[state.currentImageIndex]);
    };

    document.getElementById('imgNextBtn').onclick = () => {
      if (images.length === 0) return;
      state.currentImageIndex = (state.currentImageIndex + 1) % images.length;
      openPreviewModal(images[state.currentImageIndex]);
    };
  }

  function renderAudioModal(file, container) {
    container.innerHTML = `
      <div class="audio-player-container">
        <div style="font-size: 2.5rem;">🎵</div>
        <audio controls autoplay src="/api/files/${encodeURIComponent(file.id)}/preview"></audio>
        <div style="width: 100%; display: flex; justify-content: space-between; font-size: 0.85rem; color: var(--text-secondary);">
          <span>Format: <strong>${escapeHtml(file.mime_type)}</strong></span>
          <span>Size: <strong>${escapeHtml(file.size_human)}</strong></span>
        </div>
      </div>
    `;
  }

  function renderVideoModal(file, container) {
    container.innerHTML = `
      <div class="video-player-container">
        <video controls autoplay src="/api/files/${encodeURIComponent(file.id)}/preview"></video>
        <div style="width: 100%; display: flex; justify-content: space-between; font-size: 0.85rem; color: var(--text-secondary);">
          <span>Format: <strong>${escapeHtml(file.mime_type)}</strong></span>
          <span>Size: <strong>${escapeHtml(file.size_human)}</strong></span>
        </div>
      </div>
    `;
  }

  async function renderTextModal(file, container) {
    try {
      const res = await fetch(`/api/files/${encodeURIComponent(file.id)}/preview`);
      if (!res.ok) throw new Error('Failed to read file contents');
      const data = await res.json();
      container.innerHTML = `
        <div style="margin-bottom: 0.75rem; font-size: 0.85rem; color: var(--text-secondary);">
          Displaying sanitized text contents (${escapeHtml(file.size_human)}):
        </div>
        <pre class="text-preview-code"><code>${escapeHtml(data.content)}</code></pre>
      `;
    } catch (e) {
      container.innerHTML = `<div class="empty-state"><h3>Preview Failed</h3><p>${escapeHtml(e.message)}</p></div>`;
    }
  }

  function renderPdfModal(file, container) {
    container.innerHTML = `
      <div style="height: 60vh;">
        <iframe src="/api/files/${encodeURIComponent(file.id)}/preview" style="width: 100%; height: 100%; border: none; border-radius: var(--radius-md);"></iframe>
      </div>
    `;
  }

  async function renderDatabaseModal(file, container) {
    const meta = file.db_metadata || {};
    let encSection = '';
    if (file.is_encrypted) {
      encSection = `
        <div class="classification-box" style="margin-bottom: 1rem; border-color: var(--status-yellow);">
          <div class="classification-title" style="color: var(--status-yellow);">🔒 Encrypted Database Backup</div>
          <p style="font-size: 0.85rem; color: var(--text-secondary); margin-bottom: 0.5rem;">
            Format: <strong>${escapeHtml(meta.format_type || 'CRYPT14/15')}</strong> | Key Status: <strong>${escapeHtml(meta.key_status || 'Not checked')}</strong>
          </p>
          <p style="font-size: 0.85rem; color: var(--text-secondary);">
            WhatsApp backups are encrypted with AES-GCM-256. Decryption requires valid matching key material.
          </p>
        </div>
      `;
    }

    container.innerHTML = `
      ${encSection}
      <div style="margin-bottom: 1rem;">
        <h4 style="color: var(--accent-cyan); margin-bottom: 0.5rem;">Database Forensics</h4>
        <div style="display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 0.75rem;">
          <div class="class-item"><strong>Format</strong><p>${escapeHtml(meta.format_type || 'SQLite')}</p></div>
          <div class="class-item"><strong>Size</strong><p>${escapeHtml(file.size_human)}</p></div>
          <div class="class-item"><strong>Calculated Messages</strong><p>${meta.message_count ? meta.message_count.toLocaleString() : 'N/A'}</p></div>
          <div class="class-item"><strong>Message Date Span</strong><p>${meta.oldest_timestamp && meta.newest_timestamp ? `${escapeHtml(meta.oldest_timestamp)} to ${escapeHtml(meta.newest_timestamp)}` : 'N/A'}</p></div>
        </div>
      </div>
      <div id="dbMessagesTableContainer">
        ${file.is_sqlite && !file.is_encrypted ? '<div style="text-align: center; padding: 1rem;">Loading database records...</div>' : ''}
      </div>
    `;

    if (file.is_sqlite && !file.is_encrypted) {
      try {
        const res = await fetch(`/api/files/${encodeURIComponent(file.id)}/chat_data`);
        if (res.ok) {
          const chatData = await res.json();
          const tblContainer = document.getElementById('dbMessagesTableContainer');
          if (chatData.messages && chatData.messages.length > 0) {
            let rowsHtml = chatData.messages
              .slice(0, 25)
              .map(
                (m) => `
                <tr>
                  <td>${escapeHtml(m.sender_name || m.sender_id || 'Unknown')}</td>
                  <td>${escapeHtml(m.formatted_time || 'Unknown')}</td>
                  <td>${escapeHtml(m.text_content || '')}</td>
                </tr>
              `
              )
              .join('');

            tblContainer.innerHTML = `
              <h4 style="color: var(--accent-cyan); margin-bottom: 0.5rem;">Sample Chat Records (${chatData.messages.length})</h4>
              <div class="data-table-container">
                <table class="data-table">
                  <thead>
                    <tr><th>Sender</th><th>Timestamp</th><th>Message Text</th></tr>
                  </thead>
                  <tbody>${rowsHtml}</tbody>
                </table>
              </div>
            `;
          } else {
            tblContainer.innerHTML = '<p style="color: var(--text-muted);">No readable chat message rows found in this database.</p>';
          }
        }
      } catch (e) {
        console.error(e);
      }
    }
  }

  function renderUnsupportedModal(file, container) {
    container.innerHTML = `
      <div class="empty-state">
        <div class="empty-state-icon">📦</div>
        <h3>No Direct Browser Preview Available</h3>
        <p>This file format (${escapeHtml(file.mime_type || file.filename)}) does not support inline rendering. You can safely download the original file below.</p>
        <div style="max-width: 400px; margin: 1rem auto; text-align: left; font-size: 0.85rem;" class="class-item">
          <p><strong>Filename:</strong> ${escapeHtml(file.filename)}</p>
          <p><strong>Size:</strong> ${escapeHtml(file.size_human)}</p>
          <p><strong>Source:</strong> <code>${escapeHtml(file.source_location || 'N/A')}</code></p>
          <p><strong>SHA-256:</strong> <code>${file.sha256 || 'Uncalculated'}</code></p>
        </div>
      </div>
    `;
  }

  // Bulk ZIP Downloads
  async function downloadSelectedZip() {
    if (state.selectedIds.size === 0) {
      showToast('No files selected', 'error');
      return;
    }

    showToast(`Preparing ZIP of ${state.selectedIds.size} files...`);
    try {
      const res = await fetch('/api/download/selected', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ file_ids: Array.from(state.selectedIds) }),
      });
      if (!res.ok) throw new Error('ZIP packaging failed');

      const blob = await res.blob();
      const url = window.URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = 'selected_recovered_files.zip';
      document.body.appendChild(a);
      a.click();
      a.remove();
      window.URL.revokeObjectURL(url);
      showToast('Download started for selected files ZIP');
    } catch (e) {
      showToast('Error: ' + e.message, 'error');
    }
  }

  async function downloadAllZip() {
    const cat = state.categoryFilter !== 'all' ? state.categoryFilter : null;
    const catLabel = cat ? cat : 'all categories';
    if (!confirm(`Are you sure you want to download all accessible files for ${catLabel}?`)) {
      return;
    }

    showToast(`Packaging all eligible files...`);
    try {
      const res = await fetch('/api/download/all', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ category: cat }),
      });
      if (!res.ok) throw new Error('Packaging all files failed');

      const blob = await res.blob();
      const url = window.URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = cat ? `all_${cat.toLowerCase()}_files.zip` : 'all_recovered_files.zip';
      document.body.appendChild(a);
      a.click();
      a.remove();
      window.URL.revokeObjectURL(url);
      showToast('Download started for recovery archive');
    } catch (e) {
      showToast('Error: ' + e.message, 'error');
    }
  }

  // Event Listeners
  function setupEventListeners() {
    // Session change
    elements.sessionSelect.addEventListener('change', (e) => {
      selectSession(e.target.value);
    });

    // Nav tabs
    elements.navTabs.addEventListener('click', (e) => {
      const btn = e.target.closest('.tab-btn');
      if (btn) switchTab(btn.dataset.tab);
    });

    // Search and filters
    elements.searchInput.addEventListener('input', (e) => {
      state.searchQuery = e.target.value;
      applyFilters();
    });

    elements.statusFilter.addEventListener('change', (e) => {
      state.statusFilter = e.target.value;
      applyFilters();
    });

    elements.categoryFilter.addEventListener('change', (e) => {
      state.categoryFilter = e.target.value;
      applyFilters();
    });

    elements.sortSelect.addEventListener('change', (e) => {
      state.sortBy = e.target.value;
      applyFilters();
    });

    elements.selectAllBtn.addEventListener('click', selectAllFiltered);
    elements.clearFilterBtn.addEventListener('click', resetFilters);

    // Floating bar
    elements.downloadSelectedBtn.addEventListener('click', downloadSelectedZip);
    elements.downloadAllBtn.addEventListener('click', downloadAllZip);
    elements.clearSelectionBtn.addEventListener('click', clearSelection);

    // Modal
    elements.modalCloseBtn.addEventListener('click', closePreviewModal);
    elements.previewModal.addEventListener('click', (e) => {
      if (e.target === elements.previewModal) closePreviewModal();
    });

    // Keyboard navigation
    window.addEventListener('keydown', (e) => {
      if (e.key === 'Escape') closePreviewModal();
      if (elements.previewModal.classList.contains('open') && state.currentPreviewFile && state.currentPreviewFile.preview_type === 'image') {
        if (e.key === 'ArrowLeft') document.getElementById('imgPrevBtn')?.click();
        if (e.key === 'ArrowRight') document.getElementById('imgNextBtn')?.click();
      }
    });
  }

  // Bootstrap
  async function init() {
    setupEventListeners();
    await fetchStatus();
    await fetchSessions();
    await fetchFiles();
    renderOverviewDashboard();
  }

  window.addEventListener('DOMContentLoaded', init);
})();
