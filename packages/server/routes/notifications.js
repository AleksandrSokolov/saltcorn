/**
 * @category server
 * @module routes/notifications
 * @subcategory routes
 */

const Router = require("express-promise-router");
const { isAdmin, setTenant, error_catcher, loggedIn } = require("./utils.js");
const Notification = require("@saltcorn/data/models/notification");
const { div, a, i, text, h5, p, span } = require("@saltcorn/markup/tags");
const moment = require("moment");
const { getState } = require("@saltcorn/data/db/state");

const router = new Router();
module.exports = router;

router.get(
  "/",
  loggedIn,
  error_catcher(async (req, res) => {
    const nots = await Notification.find(
      { user_id: req.user.id },
      { orderBy: "id", orderDesc: true, limit: 20 }
    );
    await Notification.mark_as_read({
      id: { in: nots.filter((n) => !n.read).map((n) => n.id) },
    });
    const notifyCards = nots.length
      ? nots.map((not) => ({
          type: "card",
          class: [!not.read && "unread-notify"],
          contents: [
            div(
              { class: "d-flex" },
              span({ class: "fw-bold" }, not.title),
              span({ class: "ms-2 text-muted" }, moment(not.created).fromNow())
            ),
            not.body && p(not.body),
            not.link && a({ href: not.link }, "Link"),
          ],
        }))
      : [
          {
            type: "card",
            contents: [h5(req.__("No notifications"))],
          },
        ];
    res.sendWrap(req.__("Notifications"), {
      above: [
        {
          type: "breadcrumbs",
          crumbs: [{ text: req.__("Notifications") }],
        },
        ...notifyCards,
      ],
    });
  })
);

router.get(
  "/count-unread",
  loggedIn,
  error_catcher(async (req, res) => {
    const num_unread = await Notification.count({
      user_id: req.user.id,
      read: false,
    });
    res.set("Cache-Control", "public, max-age=60"); // 1 minute
    res.json({ success: num_unread });
  })
);

router.get(
  "/manifest.json",
  error_catcher(async (req, res) => {
    const state = getState();
    const manifest = {
      name: state.getConfig("site_name"),
      start_url: state.getConfig("base_url") || "/",
      display: state.getConfig("pwa_display", "browser"),
    };
    const site_logo = state.getConfig("site_logo_id");
    if (site_logo)
      manifest.icons = [
        {
          src: `/files/serve/${site_logo}`,
        },
      ];
    if (state.getConfig("pwa_set_colors", false)) {
      manifest.theme_color = state.getConfig("pwa_theme_color", "black");
      manifest.background_color = state.getConfig(
        "pwa_background_color",
        "red"
      );
    }
    res.json(manifest);
  })
);
