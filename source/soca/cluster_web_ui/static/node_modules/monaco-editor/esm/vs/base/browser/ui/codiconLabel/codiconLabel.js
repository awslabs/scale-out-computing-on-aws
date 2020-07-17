/*---------------------------------------------------------------------------------------------
 *  Copyright (c) Microsoft Corporation. All rights reserved.
 *  Licensed under the MIT License. See License.txt in the project root for license information.
 *--------------------------------------------------------------------------------------------*/
import './codicon/codicon.css';
import './codicon/codicon-animations.css';
import { escape } from '../../../common/strings.js';
function expand(text) {
    return text.replace(/\$\((([a-z0-9\-]+?)(~([a-z0-9\-]*?))?)\)/gi, function (_match, _g1, name, _g3, animation) {
        return "<span class=\"codicon codicon-" + name + " " + (animation ? "codicon-animation-" + animation : '') + "\"></span>";
    });
}
export function renderCodicons(label) {
    return expand(escape(label));
}
