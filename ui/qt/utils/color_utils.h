/** @file
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef COLOR_UTILS_H
#define COLOR_UTILS_H

#include <config.h>

#include <epan/color_filters.h>

#include <QBrush>
#include <QColor>
#include <QObject>

class ColorUtils : public QObject
{
public:
    explicit ColorUtils(QObject *parent = 0);

    static QColor fromColorT(const color_t *color);
    static QColor fromColorT(color_t color);
    static const color_t toColorT(const QColor color);
    static QRgb alphaBlend(const QColor &color1, const QColor &color2, qreal alpha);
    static QRgb alphaBlend(const QBrush &brush1, const QBrush &brush2, qreal alpha);

    // ...because they don't really fit anywhere else?
    static const QColor expert_color_comment;    /* green */
    static const QColor expert_color_chat;       /* light blue */
    static const QColor expert_color_note;       /* bright turquoise */
    static const QColor expert_color_warn;       /* yellow */
    static const QColor expert_color_error;      /* pale red */
    static const QColor expert_color_foreground; /* black */
    static const QColor hidden_proto_item;       /* gray */
    static const QColor expert_color_ROSEWATER;
    static const QColor expert_color_FLAMINGO;
    static const QColor expert_color_PINK;
    static const QColor expert_color_MAUVE;
    static const QColor expert_color_RED;
    static const QColor expert_color_MAROON;
    static const QColor expert_color_PEACH;
    static const QColor expert_color_YELLOW;
    static const QColor expert_color_GREEN;
    static const QColor expert_color_TEAL;
    static const QColor expert_color_SKY;
    static const QColor expert_color_SAPPHIRE;
    static const QColor expert_color_BLUE;
    static const QColor expert_color_LAVENDER;
    static const QColor expert_color_TEXT;
    static const QColor expert_color_SUBTEXT1;
    static const QColor expert_color_SUBTEXT0;
    static const QColor expert_color_OVERLAY2;
    static const QColor expert_color_OVERLAY1;
    static const QColor expert_color_OVERLAY0;
    static const QColor expert_color_SURFACE2;
    static const QColor expert_color_SURFACE1;
    static const QColor expert_color_SURFACE0;
    static const QColor expert_color_BASE;
    static const QColor expert_color_MANTLE;
    static const QColor expert_color_CRUST;

    static const QList<QRgb> graphColors();
    static QRgb graphColor(int item);
    static QRgb sequenceColor(int item);

    /** Checks if our application is in "dark mode".
     * Dark mode is determined by comparing the application palette's window
     * text color with the window color.
     *
     * @return true if we're running in dark mode, false otherwise.
     */
    static bool themeIsDark();

    static void setScheme(int scheme);
    /**
     * Returns an appropriate link color for the current mode.
     * @return A brush suitable for setting a text color.
     */
    static QBrush themeLinkBrush();
    /**
     * Returns an appropriate HTML+CSS link style for the current mode.
     * @return A "<style>a:link { color: ... ; }</style>" string
     */
    static QString themeLinkStyle();
    /**
     * Returns either QPalette::Text or QPalette::Base as appropriate for the
     * specified foreground color
     *
     * @param color The background color.
     * @return A contrasting foreground color for the current mode / theme.
     */
    static const QColor contrastingTextColor(const QColor color);

    /**
     * Returns an appropriate background color for hovered abstract items.
     * @return The background color.
     */
    static const QColor hoverBackground();

    /**
     * Returns an appropriate warning background color for the current mode.
     * @return The background color.
     */
    static const QColor warningBackground();

    /**
     * Returns an appropriate foreground color for disabled text.
     * @return The foreground color.
     */
    static const QColor disabledForeground();

private:
    static QList<QRgb> graph_colors_;
    static QList<QRgb> sequence_colors_;
};

void color_filter_qt_add_cb(color_filter_t *colorf, void *user_data);

#endif // COLOR_UTILS_H
