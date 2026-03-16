/**
 * PropertiesService wrapper for tracking processed message IDs.
 * Uses a JSON array stored in Script Properties with a rolling window.
 */

const CACHE_KEY = 'processedMessageIds';
const MAX_CACHED_IDS = 10000;

/** @type {Set<string>|null} */
let _processedSet = null;
/** @type {string[]|null} */
let _processedList = null;
let _cacheDirty = false;

/**
 * Loads the processed ID cache from ScriptProperties (once per execution).
 */
function loadCache_() {
  if (_processedSet !== null) return;
  const raw = PropertiesService.getScriptProperties().getProperty(CACHE_KEY);
  _processedList = raw ? JSON.parse(raw) : [];
  _processedSet = new Set(_processedList);
}

/**
 * Checks if a message ID has already been processed.
 * @param {string} id
 * @returns {boolean}
 */
function isProcessed(id) {
  loadCache_();
  return _processedSet.has(id);
}

/**
 * Marks a message ID as processed (batched — call flushCache() at end of run).
 * @param {string} id
 */
function markProcessed(id) {
  loadCache_();
  if (!_processedSet.has(id)) {
    _processedSet.add(id);
    _processedList.push(id);
    _cacheDirty = true;
  }
}

/**
 * Writes the cache back to ScriptProperties. Call once at end of scan.
 */
function flushCache() {
  if (!_cacheDirty || !_processedList) return;

  // Prune if over limit — keep the most recent IDs
  if (_processedList.length > MAX_CACHED_IDS) {
    _processedList = _processedList.slice(_processedList.length - MAX_CACHED_IDS);
    _processedSet = new Set(_processedList);
  }

  PropertiesService.getScriptProperties().setProperty(CACHE_KEY, JSON.stringify(_processedList));
  _cacheDirty = false;
}

/**
 * Clears the entire processed-ID cache.
 */
function clearProcessedCache() {
  PropertiesService.getScriptProperties().deleteProperty(CACHE_KEY);
  _processedSet = null;
  _processedList = null;
  _cacheDirty = false;
}
