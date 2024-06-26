/**
 * Table Data API handler
 * Allows to manipulate with saltcorn tables data.
 *
 * Attention! Currently, you cannot insert / update users table via this api
 * because users table has specific meaning in SC and
 * not all required (mandatory) fields of user available via this api.
 * For now this is platform limitation.
 * To solve this in future needs to publish sc_role table into user tables of saltcorn.
 *
 * Documentation: https://wiki.saltcorn.com/view/ShowPage?title=API
 * @category server
 * @module routes/api
 * @subcategory routes
 */
/** @type {module:express-promise-router} */
const Router = require("express-promise-router");
//const db = require("@saltcorn/data/db");
const { error_catcher } = require("./utils.js");
//const { mkTable, renderForm, link, post_btn } = require("@saltcorn/markup");
const { getState } = require("@saltcorn/data/db/state");
const {
  prepare_update_row,
  prepare_insert_row,
} = require("@saltcorn/data/web-mobile-commons");
const Table = require("@saltcorn/data/models/table");
const View = require("@saltcorn/data/models/view");
//const Field = require("@saltcorn/data/models/field");
const Trigger = require("@saltcorn/data/models/trigger");
//const load_plugins = require("../load_plugins");
const passport = require("passport");

const {
  readState,
  strictParseInt,
  stateFieldsToWhere,
} = require("@saltcorn/data/plugin-helper");
const Crash = require("@saltcorn/data/models/crash");

/**
 * @type {object}
 * @const
 * @namespace apiRouter
 * @category server
 * @subcategory routes
 */
const router = new Router();
module.exports = router;

/**
 * @param {*} fields
 * @returns {*}
 */
const limitFields = (fields) => (r) => {
  if (fields) {
    let res = {};

    fields.split(",").forEach((f) => {
      res[f] = r[f];
    });
    return res;
  } else {
    return r;
  }
};

/**
 * Check that user has right to read table data (only read in terms of CRUD)
 * @param {object} req httprequest
 * @param {object} user - user based on access token
 * @param {Table} table
 * @returns {boolean}
 */
function accessAllowedRead(req, user, table, allow_ownership) {
  const role =
    req.user && req.user.id
      ? req.user.role_id
      : user && user.role_id
      ? user.role_id
      : 100;

  return (
    role <= table.min_role_read ||
    ((req.user?.id || user?.id) &&
      allow_ownership &&
      (table.ownership_field_id || table.ownership_formula))
  );
}

/**
 * Check that user has right to write table data (create, update, delete in terms of  CRUD)
 * @param {object} req httprequest
 * @param {object} user user based on access token
 * @param {Table} table
 * @returns {boolean}
 */
function accessAllowedWrite(req, user, table) {
  const role =
    req.user && req.user.id
      ? req.user.role_id
      : user && user.role_id
      ? user.role_id
      : 100;

  return (
    role <= table.min_role_write ||
    ((req.user?.id || user?.id) &&
      (table.ownership_field_id || table.ownership_formula))
  );
}

/**
 * Select Table rows using GET
 * @name get/:tableName/
 * @function
 * @memberof module:routes/api~apiRouter
 */
// todo add paging
router.get(
  "/:tableName/",
  //passport.authenticate("api-bearer", { session: false }),
  error_catcher(async (req, res, next) => {
    let { tableName } = req.params;

    const { fields, versioncount, approximate, dereference, ...req_query } =
      req.query;
      
    const table = Table.findOne(
      strictParseInt(tableName)
        ? { id: strictParseInt(tableName) }
        : { name: tableName }
    );
    if (!table) {
      getState().log(3, `API get ${tableName} table not found`);
      res.status(404).json({ error: req.__("Not found") });
      return;
    }

    await passport.authenticate(
      ["api-bearer", "jwt"],
      { session: false },
      async function (err, user, info) {
        if (accessAllowedRead(req, user, table, true)) {
          let rows;
          if (versioncount === "on") {
            const joinOpts = {
              orderBy: "id",
              forUser: req.user || user || { role_id: 100 },
              forPublic: !(req.user || user),
              aggregations: {
                _versions: {
                  table: table.name + "__history",
                  ref: "id",
                  field: "id",
                  aggregate: "count",
                },
              },
            };
            rows = await table.getJoinedRows(joinOpts);
          } else {
            const tbl_fields = table.getFields();
            readState(req_query, tbl_fields, req);
            const qstate = await stateFieldsToWhere({
              fields: tbl_fields,
              approximate: !!approximate,
              state: req_query,
              table,
            });
            const joinFields = {};
            const derefs = Array.isArray(dereference)
              ? dereference
              : !dereference
              ? []
              : [dereference];
            derefs.forEach((f) => {
              const field = table.getField(f);
              if (field?.attributes?.summary_field)
                joinFields[`${f}_${field?.attributes?.summary_field}`] = {
                  ref: f,
                  target: field?.attributes?.summary_field,
                };
            });
            rows = await table.getJoinedRows({
              where: qstate,
              joinFields,
              forPublic: !(req.user || user),
              forUser: req.user || user,
            });
          }
          res.json({ success: rows.map(limitFields(fields)) });
        } else {
          getState().log(3, `API get ${table.name} not authorized`);
          res.status(401).json({ error: req.__("Not authorized") });
        }
      }
    )(req, res, next);
  })
);

/**
 * Insert into Table using POST
 * @name post/:tableName/
 * @function
 * @memberof module:routes/api~apiRouter
 */
router.post(
  "/:tableName/",
  error_catcher(async (req, res, next) => {
    const { tableName } = req.params;
    const table = Table.findOne({ name: tableName });
    if (!table) {
      getState().log(3, `API POST ${tableName} not found`);
      res.status(404).json({ error: req.__("Not found") });
      return;
    }
    await passport.authenticate(
      "api-bearer",
      { session: false },
      async function (err, user, info) {
        if (accessAllowedWrite(req, user, table)) {
          const { _versions, ...row } = req.body;
          const fields = table.getFields();
          readState(row, fields, req);
          const errors = await prepare_insert_row(row, fields);
          if (errors.length > 0) {
            getState().log(2, `API POST ${table.name} error: ${errors.join(", ")}` );
            res.status(400).json({ error: errors.join(", ") });
            return;
          }
          const ins_res = await table.tryInsertRow(
            row,
            req.user || user || { role_id: 100 }
          );
          if (ins_res.error) {
            getState().log(2, `API POST ${table.name} error: ${ins_res.error}`);
            res.status(400).json(ins_res);
          } else res.json(ins_res);
        } else {
          getState().log(3, `API POST ${table.name} not authorized`);
          res.status(401).json({ error: req.__("Not authorized") });
        }
      }
    )(req, res, next);
  })
);

/**
 * Update Table row directed by ID using POST
 * POST api/<table>/id
 * @name post/:tableName/:id
 * @function
 * @memberof module:routes/api~apiRouter
 */
router.post(
  "/:tableName/:id",
  error_catcher(async (req, res, next) => {
    const { tableName, id } = req.params;
    const table = Table.findOne({ name: tableName });
    if (!table) {
      getState().log(3, `API POST ${tableName} not found`);
      res.status(404).json({ error: req.__("Not found") });
      return;
    }
    await passport.authenticate(
      ["api-bearer", "jwt"],
      { session: false },
      async function (err, user, info) {
        if (accessAllowedWrite(req, user, table)) {
          const { _versions, ...row } = req.body;
          const fields = table.getFields();
          readState(row, fields, req);
          const errors = await prepare_update_row(table, row, id);
          if (errors.length > 0) {
            getState().log(
              2,
              `API POST ${table.name} error: ${errors.join(", ")}`
            );
            res.status(400).json({ error: errors.join(", ") });
            return;
          }
          const ins_res = await table.tryUpdateRow(
            row,
            id,
            user || req.user || { role_id: 100 }
          );

          if (ins_res.error) {
            getState().log(2, `API POST ${table.name} error: ${ins_res.error}`);
            res.status(400).json(ins_res);
          } else res.json(ins_res);
        } else {
          getState().log(3, `API POST ${table.name} not authorized`);
          res.status(401).json({ error: req.__("Not authorized") });
        }
      }
    )(req, res, next);
  })
);

/**
 * Delete Table row by ID using DELETE
 * @name delete/:tableName/:id
 * @function
 * @memberof module:routes/api~apiRouter
 */
router.delete(
  "/:tableName/:id",
  // in case of primary key different from id - id will be string "undefined"
  error_catcher(async (req, res, next) => {
    const { tableName, id } = req.params;
    const table = Table.findOne({ name: tableName });
    if (!table) {
      getState().log(3, `API DELETE ${tableName} not found`);
      res.status(404).json({ error: req.__("Not found") });
      return;
    }
    await passport.authenticate(
      "api-bearer",
      { session: false },
      async function (err, user, info) {
        if (accessAllowedWrite(req, user, table)) {
          try {
            if (id === "undefined") {
              const pk_name = table.pk_name;
              //const fields = table.getFields();
              const row = req.body;
              //readState(row, fields);
              await table.deleteRows(
                { [pk_name]: row[pk_name] },
                user || req.user || { role_id: 100 }
              );
            } else
              await table.deleteRows(
                { id },
                user || req.user || { role_id: 100 }
              );
            res.json({ success: true });
          } catch (e) {
            getState().log(2, `API DELETE ${table.name} error: ${e.message}`);
            res.status(400).json({ error: e.message });
          }
        } else {
          getState().log(3, `API DELETE ${table.name} not authorized`);
          res.status(401).json({ error: req.__("Not authorized") });
        }
      }
    )(req, res, next);
  })
);
