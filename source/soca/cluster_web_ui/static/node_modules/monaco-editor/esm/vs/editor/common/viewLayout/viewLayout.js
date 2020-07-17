/*---------------------------------------------------------------------------------------------
 *  Copyright (c) Microsoft Corporation. All rights reserved.
 *  Licensed under the MIT License. See License.txt in the project root for license information.
 *--------------------------------------------------------------------------------------------*/
var __extends = (this && this.__extends) || (function () {
    var extendStatics = function (d, b) {
        extendStatics = Object.setPrototypeOf ||
            ({ __proto__: [] } instanceof Array && function (d, b) { d.__proto__ = b; }) ||
            function (d, b) { for (var p in b) if (b.hasOwnProperty(p)) d[p] = b[p]; };
        return extendStatics(d, b);
    };
    return function (d, b) {
        extendStatics(d, b);
        function __() { this.constructor = d; }
        d.prototype = b === null ? Object.create(b) : (__.prototype = b.prototype, new __());
    };
})();
import { Disposable } from '../../../base/common/lifecycle.js';
import { Scrollable } from '../../../base/common/scrollable.js';
import { LinesLayout } from './linesLayout.js';
import { Viewport } from '../viewModel/viewModel.js';
var SMOOTH_SCROLLING_TIME = 125;
var ViewLayout = /** @class */ (function (_super) {
    __extends(ViewLayout, _super);
    function ViewLayout(configuration, lineCount, scheduleAtNextAnimationFrame) {
        var _this = _super.call(this) || this;
        _this._configuration = configuration;
        var options = _this._configuration.options;
        var layoutInfo = options.get(103 /* layoutInfo */);
        _this._linesLayout = new LinesLayout(lineCount, options.get(47 /* lineHeight */));
        _this.scrollable = _this._register(new Scrollable(0, scheduleAtNextAnimationFrame));
        _this._configureSmoothScrollDuration();
        _this.scrollable.setScrollDimensions({
            width: layoutInfo.contentWidth,
            height: layoutInfo.contentHeight
        });
        _this.onDidScroll = _this.scrollable.onScroll;
        _this._updateHeight();
        return _this;
    }
    ViewLayout.prototype.dispose = function () {
        _super.prototype.dispose.call(this);
    };
    ViewLayout.prototype.onHeightMaybeChanged = function () {
        this._updateHeight();
    };
    ViewLayout.prototype._configureSmoothScrollDuration = function () {
        this.scrollable.setSmoothScrollDuration(this._configuration.options.get(83 /* smoothScrolling */) ? SMOOTH_SCROLLING_TIME : 0);
    };
    // ---- begin view event handlers
    ViewLayout.prototype.onConfigurationChanged = function (e) {
        var options = this._configuration.options;
        if (e.hasChanged(47 /* lineHeight */)) {
            this._linesLayout.setLineHeight(options.get(47 /* lineHeight */));
        }
        if (e.hasChanged(103 /* layoutInfo */)) {
            var layoutInfo = options.get(103 /* layoutInfo */);
            var width = layoutInfo.contentWidth;
            var height = layoutInfo.contentHeight;
            var scrollDimensions = this.scrollable.getScrollDimensions();
            var scrollWidth = scrollDimensions.scrollWidth;
            var scrollHeight = this._getTotalHeight(width, height, scrollWidth);
            this.scrollable.setScrollDimensions({
                width: width,
                height: height,
                scrollHeight: scrollHeight
            });
        }
        else {
            this._updateHeight();
        }
        if (e.hasChanged(83 /* smoothScrolling */)) {
            this._configureSmoothScrollDuration();
        }
    };
    ViewLayout.prototype.onFlushed = function (lineCount) {
        this._linesLayout.onFlushed(lineCount);
    };
    ViewLayout.prototype.onLinesDeleted = function (fromLineNumber, toLineNumber) {
        this._linesLayout.onLinesDeleted(fromLineNumber, toLineNumber);
    };
    ViewLayout.prototype.onLinesInserted = function (fromLineNumber, toLineNumber) {
        this._linesLayout.onLinesInserted(fromLineNumber, toLineNumber);
    };
    // ---- end view event handlers
    ViewLayout.prototype._getHorizontalScrollbarHeight = function (width, scrollWidth) {
        var options = this._configuration.options;
        var scrollbar = options.get(74 /* scrollbar */);
        if (scrollbar.horizontal === 2 /* Hidden */) {
            // horizontal scrollbar not visible
            return 0;
        }
        if (width >= scrollWidth) {
            // horizontal scrollbar not visible
            return 0;
        }
        return scrollbar.horizontalScrollbarSize;
    };
    ViewLayout.prototype._getTotalHeight = function (width, height, scrollWidth) {
        var options = this._configuration.options;
        var result = this._linesLayout.getLinesTotalHeight();
        if (options.get(76 /* scrollBeyondLastLine */)) {
            result += height - options.get(47 /* lineHeight */);
        }
        else {
            result += this._getHorizontalScrollbarHeight(width, scrollWidth);
        }
        return Math.max(height, result);
    };
    ViewLayout.prototype._updateHeight = function () {
        var scrollDimensions = this.scrollable.getScrollDimensions();
        var width = scrollDimensions.width;
        var height = scrollDimensions.height;
        var scrollWidth = scrollDimensions.scrollWidth;
        var scrollHeight = this._getTotalHeight(width, height, scrollWidth);
        this.scrollable.setScrollDimensions({
            scrollHeight: scrollHeight
        });
    };
    // ---- Layouting logic
    ViewLayout.prototype.getCurrentViewport = function () {
        var scrollDimensions = this.scrollable.getScrollDimensions();
        var currentScrollPosition = this.scrollable.getCurrentScrollPosition();
        return new Viewport(currentScrollPosition.scrollTop, currentScrollPosition.scrollLeft, scrollDimensions.width, scrollDimensions.height);
    };
    ViewLayout.prototype.getFutureViewport = function () {
        var scrollDimensions = this.scrollable.getScrollDimensions();
        var currentScrollPosition = this.scrollable.getFutureScrollPosition();
        return new Viewport(currentScrollPosition.scrollTop, currentScrollPosition.scrollLeft, scrollDimensions.width, scrollDimensions.height);
    };
    ViewLayout.prototype._computeScrollWidth = function (maxLineWidth, viewportWidth) {
        var options = this._configuration.options;
        var wrappingInfo = options.get(104 /* wrappingInfo */);
        var isViewportWrapping = wrappingInfo.isViewportWrapping;
        if (!isViewportWrapping) {
            var extraHorizontalSpace = options.get(75 /* scrollBeyondLastColumn */) * options.get(32 /* fontInfo */).typicalHalfwidthCharacterWidth;
            var whitespaceMinWidth = this._linesLayout.getWhitespaceMinWidth();
            return Math.max(maxLineWidth + extraHorizontalSpace, viewportWidth, whitespaceMinWidth);
        }
        return Math.max(maxLineWidth, viewportWidth);
    };
    ViewLayout.prototype.onMaxLineWidthChanged = function (maxLineWidth) {
        var newScrollWidth = this._computeScrollWidth(maxLineWidth, this.getCurrentViewport().width);
        this.scrollable.setScrollDimensions({
            scrollWidth: newScrollWidth
        });
        // The height might depend on the fact that there is a horizontal scrollbar or not
        this._updateHeight();
    };
    // ---- view state
    ViewLayout.prototype.saveState = function () {
        var currentScrollPosition = this.scrollable.getFutureScrollPosition();
        var scrollTop = currentScrollPosition.scrollTop;
        var firstLineNumberInViewport = this._linesLayout.getLineNumberAtOrAfterVerticalOffset(scrollTop);
        var whitespaceAboveFirstLine = this._linesLayout.getWhitespaceAccumulatedHeightBeforeLineNumber(firstLineNumberInViewport);
        return {
            scrollTop: scrollTop,
            scrollTopWithoutViewZones: scrollTop - whitespaceAboveFirstLine,
            scrollLeft: currentScrollPosition.scrollLeft
        };
    };
    // ---- IVerticalLayoutProvider
    ViewLayout.prototype.changeWhitespace = function (callback) {
        return this._linesLayout.changeWhitespace(callback);
    };
    ViewLayout.prototype.getVerticalOffsetForLineNumber = function (lineNumber) {
        return this._linesLayout.getVerticalOffsetForLineNumber(lineNumber);
    };
    ViewLayout.prototype.isAfterLines = function (verticalOffset) {
        return this._linesLayout.isAfterLines(verticalOffset);
    };
    ViewLayout.prototype.getLineNumberAtVerticalOffset = function (verticalOffset) {
        return this._linesLayout.getLineNumberAtOrAfterVerticalOffset(verticalOffset);
    };
    ViewLayout.prototype.getWhitespaceAtVerticalOffset = function (verticalOffset) {
        return this._linesLayout.getWhitespaceAtVerticalOffset(verticalOffset);
    };
    ViewLayout.prototype.getLinesViewportData = function () {
        var visibleBox = this.getCurrentViewport();
        return this._linesLayout.getLinesViewportData(visibleBox.top, visibleBox.top + visibleBox.height);
    };
    ViewLayout.prototype.getLinesViewportDataAtScrollTop = function (scrollTop) {
        // do some minimal validations on scrollTop
        var scrollDimensions = this.scrollable.getScrollDimensions();
        if (scrollTop + scrollDimensions.height > scrollDimensions.scrollHeight) {
            scrollTop = scrollDimensions.scrollHeight - scrollDimensions.height;
        }
        if (scrollTop < 0) {
            scrollTop = 0;
        }
        return this._linesLayout.getLinesViewportData(scrollTop, scrollTop + scrollDimensions.height);
    };
    ViewLayout.prototype.getWhitespaceViewportData = function () {
        var visibleBox = this.getCurrentViewport();
        return this._linesLayout.getWhitespaceViewportData(visibleBox.top, visibleBox.top + visibleBox.height);
    };
    ViewLayout.prototype.getWhitespaces = function () {
        return this._linesLayout.getWhitespaces();
    };
    // ---- IScrollingProvider
    ViewLayout.prototype.getScrollWidth = function () {
        var scrollDimensions = this.scrollable.getScrollDimensions();
        return scrollDimensions.scrollWidth;
    };
    ViewLayout.prototype.getScrollHeight = function () {
        var scrollDimensions = this.scrollable.getScrollDimensions();
        return scrollDimensions.scrollHeight;
    };
    ViewLayout.prototype.getCurrentScrollLeft = function () {
        var currentScrollPosition = this.scrollable.getCurrentScrollPosition();
        return currentScrollPosition.scrollLeft;
    };
    ViewLayout.prototype.getCurrentScrollTop = function () {
        var currentScrollPosition = this.scrollable.getCurrentScrollPosition();
        return currentScrollPosition.scrollTop;
    };
    ViewLayout.prototype.validateScrollPosition = function (scrollPosition) {
        return this.scrollable.validateScrollPosition(scrollPosition);
    };
    ViewLayout.prototype.setScrollPositionNow = function (position) {
        this.scrollable.setScrollPositionNow(position);
    };
    ViewLayout.prototype.setScrollPositionSmooth = function (position) {
        this.scrollable.setScrollPositionSmooth(position);
    };
    ViewLayout.prototype.deltaScrollNow = function (deltaScrollLeft, deltaScrollTop) {
        var currentScrollPosition = this.scrollable.getCurrentScrollPosition();
        this.scrollable.setScrollPositionNow({
            scrollLeft: currentScrollPosition.scrollLeft + deltaScrollLeft,
            scrollTop: currentScrollPosition.scrollTop + deltaScrollTop
        });
    };
    return ViewLayout;
}(Disposable));
export { ViewLayout };
