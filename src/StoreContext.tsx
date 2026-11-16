import React, {
  createContext,
  useContext,
  useState,
  useEffect,
  useCallback,
  useMemo,
} from "react";
import { load, Store } from "@tauri-apps/plugin-store";
import { readInitialStoreValues } from "./anisette";

export const StoreContext = createContext<{
  storeValues: { [key: string]: any };
  setStoreValue: (key: string, value: any) => void;
  store: Store | null;
  storeInitialized: boolean;
}>({
  storeValues: {},
  setStoreValue: () => {},
  store: null,
  storeInitialized: false,
});

export const StoreProvider: React.FC<{ children: React.ReactNode }> = ({
  children,
}) => {
  const [storeValues, setStoreValues] = useState<{ [key: string]: any }>({});
  const [store, setStore] = useState<Store | null>(null);
  const [storeInitialized, setStoreInitialized] = useState(false);

  useEffect(() => {
    const initializeStore = async () => {
      const storeInstance = await load("preferences.json");
      // Runs the one-time move to the Mac-backed anisette servers (see anisette.ts)
      // before reading the values, so components never see the old server.
      const values = await readInitialStoreValues(storeInstance);
      setStore(storeInstance);
      setStoreValues(values);
      setStoreInitialized(true);
    };

    initializeStore();
  }, []);

  const setStoreValue = useCallback(
    async (key: string, value: any) => {
      if (!store) return;

      setStoreValues((prevValues) => {
        const newValues = { ...prevValues, [key]: value };
        return newValues;
      });

      await store.set(key, value);
      await store.save();
    },
    [store]
  );

  const contextValue = useMemo(
    () => ({ storeValues, setStoreValue, store, storeInitialized }),
    [storeValues, setStoreValue, store]
  );

  if (!store || !storeInitialized) {
    return null;
  }

  return (
    <StoreContext.Provider value={contextValue}>
      {children}
    </StoreContext.Provider>
  );
};

export const useStore = <T,>(
  key: string,
  initialValue: T
): [T, (value: T | ((oldValue: T) => T)) => void, boolean] => {
  const { storeValues, setStoreValue, storeInitialized } =
    useContext(StoreContext);
  const [value, setValue] = useState<T>(storeValues[key] ?? initialValue);

  useEffect(() => {
    if (storeValues[key] !== undefined && storeValues[key] !== value) {
      setValue(storeValues[key]);
    }
  }, [storeValues, key]);

  const setStoredValue = useCallback(
    (newValue: T | ((oldValue: T) => T)) => {
      const valueToStore =
        typeof newValue === "function"
          ? (newValue as (oldValue: T) => T)(value)
          : newValue;
      setValue(valueToStore);
      setStoreValue(key, valueToStore);
    },
    [key, setStoreValue, value]
  );

  return [value, setStoredValue, storeInitialized];
};
