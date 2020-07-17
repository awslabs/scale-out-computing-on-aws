/*---------------------------------------------------------------------------------------------
 *  Copyright (c) Microsoft Corporation. All rights reserved.
 *  Licensed under the MIT License. See License.txt in the project root for license information.
 *--------------------------------------------------------------------------------------------*/
import './keybindingLabel.css';
import { equals } from '../../../common/objects.js';
import { UILabelProvider } from '../../../common/keybindingLabels.js';
import * as dom from '../../dom.js';
import { localize } from '../../../../nls.js';
var $ = dom.$;
var KeybindingLabel = /** @class */ (function () {
    function KeybindingLabel(container, os, options) {
        this.os = os;
        this.options = options;
        this.domNode = dom.append(container, $('.monaco-keybinding'));
        this.didEverRender = false;
        container.appendChild(this.domNode);
    }
    KeybindingLabel.prototype.set = function (keybinding, matches) {
        if (this.didEverRender && this.keybinding === keybinding && KeybindingLabel.areSame(this.matches, matches)) {
            return;
        }
        this.keybinding = keybinding;
        this.matches = matches;
        this.render();
    };
    KeybindingLabel.prototype.render = function () {
        dom.clearNode(this.domNode);
        if (this.keybinding) {
            var _a = this.keybinding.getParts(), firstPart = _a[0], chordPart = _a[1];
            if (firstPart) {
                this.renderPart(this.domNode, firstPart, this.matches ? this.matches.firstPart : null);
            }
            if (chordPart) {
                dom.append(this.domNode, $('span.monaco-keybinding-key-chord-separator', undefined, ' '));
                this.renderPart(this.domNode, chordPart, this.matches ? this.matches.chordPart : null);
            }
            this.domNode.title = this.keybinding.getAriaLabel() || '';
        }
        else if (this.options && this.options.renderUnboundKeybindings) {
            this.renderUnbound(this.domNode);
        }
        this.didEverRender = true;
    };
    KeybindingLabel.prototype.renderPart = function (parent, part, match) {
        var _a, _b, _c, _d, _e;
        var modifierLabels = UILabelProvider.modifierLabels[this.os];
        if (part.ctrlKey) {
            this.renderKey(parent, modifierLabels.ctrlKey, Boolean((_a = match) === null || _a === void 0 ? void 0 : _a.ctrlKey), modifierLabels.separator);
        }
        if (part.shiftKey) {
            this.renderKey(parent, modifierLabels.shiftKey, Boolean((_b = match) === null || _b === void 0 ? void 0 : _b.shiftKey), modifierLabels.separator);
        }
        if (part.altKey) {
            this.renderKey(parent, modifierLabels.altKey, Boolean((_c = match) === null || _c === void 0 ? void 0 : _c.altKey), modifierLabels.separator);
        }
        if (part.metaKey) {
            this.renderKey(parent, modifierLabels.metaKey, Boolean((_d = match) === null || _d === void 0 ? void 0 : _d.metaKey), modifierLabels.separator);
        }
        var keyLabel = part.keyLabel;
        if (keyLabel) {
            this.renderKey(parent, keyLabel, Boolean((_e = match) === null || _e === void 0 ? void 0 : _e.keyCode), '');
        }
    };
    KeybindingLabel.prototype.renderKey = function (parent, label, highlight, separator) {
        dom.append(parent, $('span.monaco-keybinding-key' + (highlight ? '.highlight' : ''), undefined, label));
        if (separator) {
            dom.append(parent, $('span.monaco-keybinding-key-separator', undefined, separator));
        }
    };
    KeybindingLabel.prototype.renderUnbound = function (parent) {
        dom.append(parent, $('span.monaco-keybinding-key', undefined, localize('unbound', "Unbound")));
    };
    KeybindingLabel.areSame = function (a, b) {
        if (a === b || (!a && !b)) {
            return true;
        }
        return !!a && !!b && equals(a.firstPart, b.firstPart) && equals(a.chordPart, b.chordPart);
    };
    return KeybindingLabel;
}());
export { KeybindingLabel };
