## ============================================================================
## Google User Implementation
## Native implementation for GoogleUser class
## ============================================================================

import harding/core/types
import harding/interpreter/objects

type
  GoogleUserData = object
    id: string
    email: string
    name: string
    givenName: string
    familyName: string
    picture: string
    locale: string
    verifiedEmail: bool

proc googleUserNewImpl*(interp: var Interpreter, self: Instance,
                         args: seq[NodeValue]): NodeValue {.nimcall.} =
  ## Create a new GoogleUser instance

  let objectCls = interp.globals[]["Object"]
  if objectCls.kind != vkClass:
    return nilValue()

  let userClsVal = interp.globals[]["GoogleUser"]
  if userClsVal.kind != vkClass:
    return nilValue()

  let userCls = userClsVal.classVal
  let instance = newInstance(userCls)

  var userData = GoogleUserData(
    id: "",
    email: "",
    name: "",
    givenName: "",
    familyName: "",
    picture: "",
    locale: "",
    verifiedEmail: false
  )

  var dataPtr = create(GoogleUserData)
  dataPtr[] = userData
  instance.nimValue = cast[pointer](dataPtr)
  instance.isNimProxy = true

  return instance.toValue()

# Helper proc to set instance slots
proc setInstanceSlot*(instance: Instance, slotName: string, value: NodeValue) =
  ## Set a slot value on an instance
  if instance.slots.hasKey(slotName):
    instance.slots[slotName] = value
  else:
    # Try to find the slot in the class hierarchy
    var cls = instance.class
    while cls != nil:
      if slotName in cls.slots:
        instance.slots[slotName] = value
        return
      cls = cls.super
