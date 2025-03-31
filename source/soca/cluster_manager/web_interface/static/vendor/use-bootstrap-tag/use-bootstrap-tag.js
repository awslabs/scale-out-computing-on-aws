var UseBootstrapTag = function() {
  "use strict";
  const context = [];
  function cleanup(observer) {
    for (const dep of observer.dependencies) {
      dep.delete(observer);
    }
    observer.dependencies.clear();
  }
  function subscribe(observer, subscriptions) {
    subscriptions.add(observer);
    observer.dependencies.add(subscriptions);
  }
  function state(value) {
    const subscriptions = /* @__PURE__ */ new Set();
    function read() {
      const observer = context[context.length - 1];
      if (observer) {
        subscribe(observer, subscriptions);
      }
      return value;
    }
    function write(newValue) {
      value = newValue;
      for (const observer of [...subscriptions]) {
        observer.execute();
      }
    }
    return [read, write];
  }
  function effect(fn) {
    const effect2 = {
      execute() {
        cleanup(effect2);
        context.push(effect2);
        fn();
        context.pop();
      },
      dependencies: /* @__PURE__ */ new Set()
    };
    effect2.execute();
  }
  function arraysAreEqual(arr1, arr2) {
    return arr1.length === arr2.length && arr1.every((value, index) => value === arr2[index]);
  }
  function change(target, value) {
    target.value = value;
    target.dispatchEvent(new Event("change"));
  }
  function pull(items, value) {
    const i = items.lastIndexOf(value);
    i !== -1 && items.splice(i, 1);
  }
  function createElement(tagName, attributes) {
    const element = document.createElement(tagName);
    return Object.assign(element, attributes);
  }
  function processData(data, separator) {
    return typeof data === "string" ? data.split(separator) : Array.isArray(data) ? data.flatMap((item) => typeof item === "string" ? item.split(separator) : []) : [];
  }
  const name = "use-bootstrap-tag";
  const classTarget = `${name}-target`;
  function UseBootstrapTag2(element) {
    const target = element;
    const nextElement = target.nextElementSibling;
    if (nextElement && nextElement.classList.contains(name)) {
      nextElement.remove();
    }
    const root = createElement("div");
    target.insertAdjacentElement("afterend", root);
    const dataset = target.dataset;
    const config = {
      separator: dataset.ubTagSeparator || ",",
      variant: dataset.ubTagVariant || "secondary",
      xPosition: dataset.ubTagXPosition || "right",
      transform: dataset.ubTagTransform || "input => input",
      isDuplicate: dataset.ubTagDuplicate !== void 0,
      max: +dataset.ubTagMax > 0 ? +dataset.ubTagMax : void 0,
      noInputOnblur: dataset.ubTagNoInputOnblur !== void 0
    };
    const tags = () => root.querySelectorAll("button");
    const animateTag = (tag) => {
      tag.classList.add("duplicate");
      setTimeout(() => {
        tag.classList.remove("duplicate");
      }, 150);
    };
    const getValue = () => target.value;
    const getValues = () => getValue().split(config.separator).filter((i) => i !== "");
    const addValue = (value2) => {
      const values2 = getValues();
      const insert = processData(value2, config.separator);
      if (!config.max || values2.length < config.max) {
        const duplicates = [];
        !config.isDuplicate && values2.forEach((value3, index) => insert.includes(value3) && duplicates.push(index));
        const inserted = [];
        insert.forEach((i) => {
          if (values2.includes(i)) {
            config.isDuplicate && inserted.push(i);
          } else {
            inserted.push(i);
          }
        });
        values2.push(...inserted);
        if (!arraysAreEqual(getValues(), values2)) {
          change(target, values2.join(config.separator));
          inserted.forEach((item) => {
            const tag = tags()[values2.lastIndexOf(item)];
            const tagHeight = tag.offsetHeight;
            tag.style.height = 0;
            setTimeout(() => tag.style.height = `${tagHeight}px`, 0);
            setTimeout(() => tag.style.removeProperty("height"), 150);
          });
        }
        if (!config.isDuplicate) {
          duplicates.forEach((index) => animateTag(tags()[index]));
        }
      } else {
        insert.length > 0 && tags().forEach(animateTag);
      }
    };
    const removeValue = (value2) => {
      const values2 = getValues();
      const remove = processData(value2, config.separator);
      remove.forEach((i) => pull(values2, i));
      if (!arraysAreEqual(getValues(), values2)) {
        change(target, values2.join(config.separator));
      }
    };
    const classList = target.classList;
    const disabled = target.disabled;
    target.tabIndex = -1;
    classList.add(classTarget);
    const [value, setValue] = state(target.value);
    const [focus, setFocus] = state(false);
    const [text, setText] = state("");
    const values = () => value().split(config.separator).filter((i) => i.trim() !== "");
    const texts = () => Function(`return ${config.transform}`)()(text().trim());
    const placeholder = () => values().length ? "" : target.placeholder;
    root.className = `${name} d-flex flex-wrap align-items-center gap-1 ${classList.value}`.replace(classTarget, "");
    effect(() => {
      focus() ? root.classList.add("focus") : root.classList.remove("focus");
    });
    const textFocus = () => {
      var _a;
      return (_a = root.querySelector("input")) == null ? void 0 : _a.focus();
    };
    const removeByIndex = (index) => {
      if (index >= 0) {
        removeValue(values()[index]);
      }
    };
    const appendTag = (force = false) => {
      const value2 = texts();
      value2 === "" && setText("");
      if (text().includes(config.separator) || force && text() !== "") {
        addValue(value2.split(config.separator).filter((i) => i.trim() !== ""));
        setText("");
      }
    };
    const tagElement = createElement("button", {
      type: "button",
      className: `align-items-center d-inline-flex py-0 border-0 ml-1 btn btn-sm btn-${config.variant}`,
      disabled
    });
    classList.contains("form-control-sm") && tagElement.classList.add("btn-sm");
    classList.contains("form-control-lg") && tagElement.classList.add("btn-lg");
    config.xPosition === "left" && tagElement.classList.add("flex-row-reverse");
    const closeTagElement = createElement("span", {
      className: "d-inline-flex",
      role: "button",
      tabIndex: -1,
      innerHTML: '<svg xmlns="http://www.w3.org/2000/svg" width="1em" height="1em" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><line x1="18" y1="6" x2="6" y2="18" /><line x1="6" y1="6" x2="18" y2="18" /></svg>'
    });
    const renderTags = (items) => {
      tags().forEach((tag) => tag.remove());
      items.reverse().forEach((value2, i) => {
        const index = items.length - 1 - i;
        const tag = tagElement.cloneNode();
        tag.innerHTML = value2;
        tag.onfocus = () => {
          tag.classList.add("active");
          setFocus(true);
        };
        tag.onblur = () => {
          tag.classList.remove("active");
          setFocus(false);
        };
        tag.onkeydown = ({
          key
        }) => {
          if (key === "Backspace" || key === "Delete") {
            removeByIndex(index);
            const nextFocus = key === "Backspace" ? index - 1 : values().length === index ? -1 : index;
            if (nextFocus === -1) {
              textFocus();
            } else {
              tags()[nextFocus].focus();
            }
          }
        };
        if (!disabled) {
          const span = closeTagElement.cloneNode(true);
          span.onclick = () => {
            removeByIndex(index);
            textFocus();
          };
          tag.append(span);
        }
        root.prepend(tag);
      });
    };
    effect(() => {
      renderTags(values());
    });
    if (!disabled) {
      const wrapper = createElement("div", {
        className: "input-wrapper"
      });
      const span = createElement("span");
      const input = createElement("input", {
        type: "text"
      });
      input.onfocus = () => {
        setFocus(true);
      };
      input.onblur = () => {
        setFocus(false);
        config.noInputOnblur ? setText("") : appendTag(true);
      };
      input.onkeydown = (e) => {
        if (text() === "" && e.key === "Backspace") {
          removeByIndex(values().length - 1);
        }
        if (text() !== "" && e.key === "Enter") {
          appendTag(true);
          e.preventDefault();
        }
      };
      input.oninput = () => {
        setText(input.value);
        appendTag();
      };
      effect(() => {
        span.innerHTML = text() || placeholder() || "i";
        input.placeholder = placeholder();
        input.value = text();
      });
      wrapper.append(span, input);
      root.append(wrapper);
    }
    root.onclick = (e) => {
      if (e.target.tagName !== "BUTTON") {
        textFocus();
      }
    };
    target.addEventListener("change", () => {
      setValue(target.value);
    });
    target.addEventListener("focus", textFocus);
    return {
      getValue,
      getValues,
      addValue,
      removeValue
    };
  }
  return UseBootstrapTag2;
}();
